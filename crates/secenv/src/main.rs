mod args;
mod auth;
mod aws;
mod gcp;
mod gpg;
mod manifest;
mod password_cipher;
mod pgp;
mod process;
mod reference;
mod sealed;

use {
    anyhow::{
        Context,
        Result,
    },
    args::{
        ManualFormat,
        SealTarget,
        UnlockAction,
    },
    manifest::Manifest,
    std::{
        collections::HashMap,
        io::Write,
        process::ExitCode,
    },
    zeroize::{
        Zeroize,
        Zeroizing,
    },
};

#[tokio::main]
async fn main() -> Result<ExitCode> {
    let command = crate::args::ClapArgumentLoader::load()?;

    match command {
        | crate::args::Command::Manual { path, format } => {
            std::fs::create_dir_all(&path)
                .with_context(|| format!("Failed to create directory: {}", path.display()))?;
            let builder = crate::reference::ReferenceBuilder;
            match format {
                | ManualFormat::Manpages => builder.build_manpages(&path)?,
                | ManualFormat::Markdown => builder.build_markdown(&path)?,
            }
            Ok(ExitCode::SUCCESS)
        },
        | crate::args::Command::Autocomplete { path, shell } => {
            std::fs::create_dir_all(&path)
                .with_context(|| format!("Failed to create directory: {}", path.display()))?;
            let builder = crate::reference::ReferenceBuilder;
            builder.build_shell_completion(&path, &shell)?;
            Ok(ExitCode::SUCCESS)
        },
        | crate::args::Command::Unlock {
            manifest,
            profile_name,
            action,
            force,
            timeout,
            password,
        } => {
            manifest.warn_if_insecure_permissions();

            let mut pgp_manager = crate::pgp::PgpManager::default();

            let profile = manifest
                .profiles
                .get(profile_name.as_str())
                .with_context(|| format!("Profile '{}' not found in manifest", profile_name))?;
            // Before the first await, so the system prompt stays on the process main
            // thread.
            crate::auth::ProfileGate::new(profile_name.as_str(), profile.auth.as_ref())
                .enforce(crate::auth::ProfileOperation::Unlock, password)?;

            let mut secret_source_env_vars: Vec<_> =
                profile.secret_environment_variables().map(str::to_owned).collect();
            secret_source_env_vars.sort_unstable();
            secret_source_env_vars.dedup();

            let generated_files: Vec<_> = profile.files.keys().cloned().collect();
            let sealed_file_manager = crate::sealed::SealedFileManager::new(manifest.source_directory()?)?;
            sealed_file_manager.validate_profile(profile.sealed.as_ref(), &generated_files, force)?;

            let mut environment = Environment::load(profile, &secret_source_env_vars)?;
            environment.remove_secret_sources(&secret_source_env_vars);

            for (key, value) in profile.env.vars.iter() {
                let value = value
                    .inner
                    .resolve(&mut pgp_manager, &secret_source_env_vars)
                    .with_context(|| format!("Failed to resolve environment variable '{}'", key))?;
                environment.insert(key.clone(), value)?;
            }

            // Resolve remote and interactive sources before materializing any
            // plaintext files. Signals retain their default behavior here.
            let mut generated_content = Vec::with_capacity(profile.files.len());
            for (file_path, content) in profile.files.iter() {
                generated_content.push((
                    file_path.clone(),
                    Zeroizing::new(
                        content
                            .inner
                            .resolve_temporary_file(&mut pgp_manager, &secret_source_env_vars)
                            .with_context(|| format!("Failed to resolve temporary file '{}'", file_path))?,
                    ),
                ));
            }

            let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel(1);
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let shutdown_handle = tokio::spawn(async move {
                let exit_code = shutdown_signal(ready_tx).await;
                let _ = shutdown_tx.send(exit_code).await;
            });
            ready_rx.await.context("Failed to initialize signal handling")??;

            let mut interrupted = None;
            let setup_result: Result<()> = {
                let mut poll_shutdown = || {
                    if interrupted.is_some() {
                        return true;
                    }
                    if let Ok(exit_code) = shutdown_rx.try_recv() {
                        interrupted = Some(exit_code);
                        return true;
                    }
                    false
                };

                (|| {
                    if let Some(sealed) = &profile.sealed {
                        sealed_file_manager.unseal(
                            sealed,
                            &generated_files,
                            &secret_source_env_vars,
                            &mut pgp_manager,
                            force,
                            &mut poll_shutdown,
                        )?;
                    }

                    for (file_path, value) in generated_content.iter_mut() {
                        if poll_shutdown() {
                            anyhow::bail!("Interrupted before plaintext files were written");
                        }
                        sealed_file_manager.write_generated(file_path, value.as_str(), force)?;
                        value.zeroize();
                    }
                    Ok(())
                })()
            };

            let execution_result: Result<ExecutionOutcome> = async {
                if let Some(exit_code) = interrupted {
                    return Ok(ExecutionOutcome::Interrupted(exit_code));
                }
                setup_result?;
                if let Ok(exit_code) = shutdown_rx.try_recv() {
                    return Ok(ExecutionOutcome::Interrupted(exit_code));
                }
                match action {
                    | UnlockAction::Run(command) => {
                        let executor =
                            CommandExecutor::new(&command, &environment, &profile.env.keep, &secret_source_env_vars);
                        executor.execute(timeout, &mut shutdown_rx).await
                    },
                    | UnlockAction::Print => {
                        let stdout = std::io::stdout();
                        let mut stdout = stdout.lock();
                        for (key, value) in environment.iter() {
                            if let Ok(exit_code) = shutdown_rx.try_recv() {
                                return Ok(ExecutionOutcome::Interrupted(exit_code));
                            }
                            writeln!(
                                stdout,
                                "export {}={}",
                                Environment::shell_escape(key),
                                Environment::shell_escape(value)
                            )
                            .context("Failed to write environment exports")?;
                        }
                        Ok(ExecutionOutcome::Printed)
                    },
                }
            }
            .await;

            let restore_result = sealed_file_manager.restore_all();
            pgp_manager.clear_cache();

            shutdown_handle.abort();
            let _ = shutdown_handle.await;
            let late_interrupt = shutdown_rx.try_recv().ok();

            restore_result?;
            let outcome = execution_result?;
            let outcome = match late_interrupt {
                | Some(exit_code) => ExecutionOutcome::Interrupted(exit_code),
                | None => outcome,
            };
            Ok(outcome.exit_code())
        },
        | crate::args::Command::Seal {
            manifest,
            profile_name,
            target,
            input,
            password,
        } => {
            manifest.warn_if_insecure_permissions();
            let profile = manifest
                .profiles
                .get(&profile_name)
                .with_context(|| format!("Profile '{}' not found in manifest", profile_name))?;
            crate::auth::ProfileGate::new(profile_name.as_str(), profile.auth.as_ref())
                .enforce(crate::auth::ProfileOperation::Seal, password)?;
            let pgp_manager = crate::pgp::PgpManager::default();
            let mut secret_source_env_vars: Vec<_> =
                profile.secret_environment_variables().map(str::to_owned).collect();
            secret_source_env_vars.sort_unstable();
            secret_source_env_vars.dedup();

            let seal_value = |plaintext: &str| -> Result<String> {
                match &target {
                    | SealTarget::Document(configured_file) => {
                        let sealed = profile
                            .sealed
                            .as_ref()
                            .with_context(|| format!("Profile '{}' has no sealed files", profile_name))?;
                        crate::sealed::SealedFileManager::new(manifest.source_directory()?)?.seal_value(
                            sealed,
                            configured_file,
                            plaintext,
                            &pgp_manager,
                            &secret_source_env_vars,
                        )
                    },
                    | SealTarget::EnvironmentVariable(name) => {
                        profile
                            .env
                            .vars
                            .get(name)
                            .with_context(|| {
                                format!(
                                    "Environment variable '{}' is not configured in profile '{}'",
                                    name, profile_name
                                )
                            })?
                            .inner
                            .seal(plaintext, &pgp_manager, &secret_source_env_vars)
                            .with_context(|| format!("Failed to seal environment variable '{}'", name))
                    },
                }
            };

            let marker = match input {
                | crate::args::SealInput::Pointer(pointer) => {
                    let SealTarget::Document(configured_file) = &target else {
                        anyhow::bail!("--path requires a document target selected with --for");
                    };
                    let sealed = profile
                        .sealed
                        .as_ref()
                        .with_context(|| format!("Profile '{}' has no sealed files", profile_name))?;
                    let manager = crate::sealed::SealedFileManager::new(manifest.source_directory()?)?;
                    manager.seal_path(sealed, configured_file, &pointer, &pgp_manager, &secret_source_env_vars)?
                },
                | crate::args::SealInput::Direct(plaintext) => seal_value(plaintext.as_str())?,
                | crate::args::SealInput::Stdin => {
                    use std::io::{
                        IsTerminal,
                        Read,
                    };

                    if std::io::stdin().is_terminal() {
                        anyhow::bail!("No VALUE provided; pass it directly or pipe plaintext on stdin");
                    }
                    let mut plaintext = Zeroizing::new(String::new());
                    std::io::stdin()
                        .read_to_string(&mut plaintext)
                        .context("Failed to read plaintext from stdin")?;
                    seal_value(plaintext.as_str())?
                },
            };
            writeln!(std::io::stdout().lock(), "{}", marker).context("Failed to write sealed marker")?;
            Ok(ExitCode::SUCCESS)
        },
        | args::Command::Init { path, force } => {
            if path.exists() && !force {
                return Err(anyhow::anyhow!(
                    "Config file '{}' already exists. Use --force to overwrite.",
                    path.display()
                ));
            }

            let manifest = Manifest::example(path.clone());

            let json_config =
                serde_json::to_string_pretty(&manifest).context("Failed to serialize example config to JSON")?;

            std::fs::write(&path, json_config)
                .with_context(|| format!("Failed to write config file: {}", path.display()))?;

            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            writeln!(stdout, "Created example configuration file: {}", path.display())?;
            writeln!(stdout, "Edit the file to add your own variables and PGP keys.")?;
            writeln!(
                stdout,
                "Note: Remove '_EXAMPLE' suffix from variable names before using them."
            )?;
            Ok(ExitCode::SUCCESS)
        },
        | args::Command::AuthPassword => {
            let verifier = crate::auth::ProfilePasswordVerifier::prompt_new()?;
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            writeln!(
                std::io::stderr(),
                "Paste this verifier into profiles.<name>.auth.password. secenv does not rewrite the config."
            )?;
            writeln!(stdout, "{}", verifier.as_str()).context("Failed to write profile password verifier")?;
            Ok(ExitCode::SUCCESS)
        },
    }
}

enum ExecutionOutcome {
    Exited(std::process::ExitStatus),
    Printed,
    Interrupted(i32),
    TimedOut,
}

impl ExecutionOutcome {
    fn exit_code(self) -> ExitCode {
        let code = match self {
            | Self::Exited(status) if status.success() => return ExitCode::SUCCESS,
            | Self::Exited(status) => status.code().unwrap_or(1),
            | Self::Printed => return ExitCode::SUCCESS,
            | Self::Interrupted(code) => code,
            | Self::TimedOut => 124,
        };
        ExitCode::from(u8::try_from(code).unwrap_or(1))
    }
}

#[cfg(unix)]
async fn shutdown_signal(ready: tokio::sync::oneshot::Sender<Result<()>>) -> i32 {
    use tokio::signal::unix::{
        signal,
        SignalKind,
    };

    let mut interrupt = match signal(SignalKind::interrupt()) {
        | Ok(interrupt) => interrupt,
        | Err(error) => {
            let _ = ready.send(Err(error).context("Failed to install SIGINT handler"));
            return 1;
        },
    };
    let mut terminate = match signal(SignalKind::terminate()) {
        | Ok(terminate) => terminate,
        | Err(error) => {
            let _ = ready.send(Err(error).context("Failed to install SIGTERM handler"));
            return 1;
        },
    };
    let _ = ready.send(Ok(()));

    tokio::select! {
        _ = interrupt.recv() => 130,
        _ = terminate.recv() => 143,
    }
}

#[cfg(windows)]
async fn shutdown_signal(ready: tokio::sync::oneshot::Sender<Result<()>>) -> i32 {
    let mut ctrl_c = match tokio::signal::windows::ctrl_c() {
        | Ok(ctrl_c) => ctrl_c,
        | Err(error) => {
            let _ = ready.send(Err(error).context("Failed to install Ctrl-C handler"));
            return 1;
        },
    };
    let _ = ready.send(Ok(()));
    let _ = ctrl_c.recv().await;
    130
}

#[derive(Default)]
struct Environment {
    values: HashMap<String, Zeroizing<String>>,
}

impl Environment {
    fn load(profile: &manifest::ManifestProfile, removed_env_vars: &[String]) -> Result<Self> {
        let mut environment = Self::default();
        for source in &profile.env.from {
            let value = Zeroizing::new(source.inner.resolve(removed_env_vars)?);
            environment.extend_from(&value)?;
        }
        Ok(environment)
    }

    fn remove_secret_sources(&mut self, names: &[String]) {
        #[cfg(windows)]
        self.values
            .retain(|name, _| !names.iter().any(|source| source.eq_ignore_ascii_case(name)));
        #[cfg(not(windows))]
        for name in names {
            self.values.remove(name);
        }
    }

    fn insert(&mut self, name: String, value: String) -> Result<()> {
        let value = Zeroizing::new(value);
        if !Self::is_valid_name(&name) {
            anyhow::bail!("Invalid environment variable name '{}'", name);
        }
        self.values.insert(name, value);
        Ok(())
    }

    fn extend_from(&mut self, value: &str) -> Result<()> {
        for (line_number, line) in value.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (name, value) = line.split_once('=').with_context(|| {
                format!(
                    "Malformed line {} in env source (missing '='): '{}'",
                    line_number + 1,
                    line
                )
            })?;
            self.insert(name.trim().to_string(), value.trim().to_string())
                .with_context(|| format!("Invalid environment variable at line {}", line_number + 1))?;
        }
        Ok(())
    }

    fn iter(&self) -> impl Iterator<Item=(&String, &Zeroizing<String>)> {
        self.values.iter()
    }

    fn is_valid_name(name: &str) -> bool {
        let mut characters = name.chars();
        matches!(characters.next(), Some(first) if first.is_ascii_alphabetic() || first == '_')
            && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
    }

    fn shell_escape(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// Builds and executes a child process with configured environment variables.
struct CommandExecutor<'a> {
    command: &'a args::ChildCommand,
    environment: &'a Environment,
    keep_env_vars: &'a Option<Vec<String>>,
    sealed_secret_env_vars: &'a [String],
}

impl<'a> CommandExecutor<'a> {
    fn new(
        command: &'a args::ChildCommand,
        environment: &'a Environment,
        keep_env_vars: &'a Option<Vec<String>>,
        sealed_secret_env_vars: &'a [String],
    ) -> Self {
        Self {
            command,
            environment,
            keep_env_vars,
            sealed_secret_env_vars,
        }
    }

    fn spawn(&self) -> Result<tokio::process::Child> {
        let mut command = tokio::process::Command::new(self.command.program());
        command.args(self.command.arguments());

        self.configure_env(&mut command)?;
        command.kill_on_drop(true);
        command
            .spawn()
            .with_context(|| format!("Failed to execute command: {}", self.command.program()))
    }

    async fn execute(
        &self,
        timeout: Option<std::time::Duration>,
        shutdown: &mut tokio::sync::mpsc::Receiver<i32>,
    ) -> Result<ExecutionOutcome> {
        let mut child = self.spawn()?;
        let timeout_elapsed = async move {
            match timeout {
                | Some(timeout) => tokio::time::sleep(timeout).await,
                | None => std::future::pending().await,
            }
        };
        tokio::pin!(timeout_elapsed);

        tokio::select! {
            biased;
            exit_code = shutdown.recv() => {
                let exit_code = exit_code.context("Shutdown monitor stopped unexpectedly")?;
                Self::terminate(&mut child, self.command.program()).await?;
                Ok(ExecutionOutcome::Interrupted(exit_code))
            },
            status = child.wait() => {
                let status = status.with_context(|| {
                    format!("Failed to wait for command: {}", self.command.program())
                })?;
                Ok(ExecutionOutcome::Exited(status))
            },
            _ = &mut timeout_elapsed => {
                Self::terminate(&mut child, self.command.program()).await?;
                Ok(ExecutionOutcome::TimedOut)
            },
        }
    }

    async fn terminate(child: &mut tokio::process::Child, program: &str) -> Result<()> {
        if let Err(error) = child.start_kill() {
            if child
                .try_wait()
                .with_context(|| format!("Failed to inspect command after termination failed: {}", program))?
                .is_none()
            {
                return Err(error).with_context(|| format!("Failed to terminate command: {}", program));
            }
        }
        child
            .wait()
            .await
            .with_context(|| format!("Failed to reap terminated command: {}", program))?;
        Ok(())
    }

    fn configure_env(&self, command: &mut tokio::process::Command) -> Result<()> {
        if let Some(patterns) = self.keep_env_vars {
            command.env_clear();

            let compiled_patterns: Result<Vec<regex::Regex>, _> = patterns
                .iter()
                .map(|pattern| {
                    regex::Regex::new(pattern)
                        .with_context(|| format!("Invalid regex pattern in env.keep: '{}'", pattern))
                })
                .collect();

            let compiled_patterns = compiled_patterns?;

            for (env_key, env_value) in std::env::vars_os() {
                for pattern in &compiled_patterns {
                    if env_key.to_str().is_some_and(|key| pattern.is_match(key)) {
                        command.env(&env_key, &env_value);
                        break;
                    }
                }
            }
        }

        for variable in self.sealed_secret_env_vars {
            command.env_remove(variable);
        }
        for (key, value) in self.environment.iter() {
            command.env(key, value.as_str());
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn environment_rejects_invalid_names() {
        let mut environment = Environment::default();
        assert!(environment
            .insert("VALID_NAME".to_string(), "value".to_string())
            .is_ok());
        assert!(environment.insert("1INVALID".to_string(), "value".to_string()).is_err());
    }

    #[tokio::test]
    async fn command_executor_spawns_and_waits_for_child() -> Result<()> {
        let command = args::ChildCommand::new("sh".to_string(), vec!["-c".to_string(), "exit 7".to_string()])?;
        let environment = Environment::default();
        let keep_env_vars = None;
        let sealed_secret_env_vars = Vec::new();
        let executor = CommandExecutor::new(&command, &environment, &keep_env_vars, &sealed_secret_env_vars);

        let status = executor.spawn()?.wait().await?;
        assert_eq!(status.code(), Some(7));
        Ok(())
    }

    #[tokio::test]
    async fn command_executor_terminates_a_timed_out_child() -> Result<()> {
        let command = args::ChildCommand::new("sleep".to_string(), vec!["10".to_string()])?;
        let environment = Environment::default();
        let keep_env_vars = None;
        let sealed_secret_env_vars = Vec::new();
        let executor = CommandExecutor::new(&command, &environment, &keep_env_vars, &sealed_secret_env_vars);
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel(1);

        let outcome = executor
            .execute(Some(std::time::Duration::from_millis(10)), &mut shutdown_rx)
            .await?;

        assert!(matches!(outcome, ExecutionOutcome::TimedOut));
        Ok(())
    }

    #[tokio::test]
    async fn command_executor_removes_sealed_secret_environment_variables() -> Result<()> {
        let command = args::ChildCommand::new("sh".to_string(), vec![])?;
        let environment = Environment::default();
        let keep_env_vars = None;
        let sealed_secret_env_vars = vec!["SECENV_TEST_SEALED_SECRET".to_string()];
        let executor = CommandExecutor::new(&command, &environment, &keep_env_vars, &sealed_secret_env_vars);
        let mut child = tokio::process::Command::new("sh");
        child
            .args(["-c", "[ -z \"${SECENV_TEST_SEALED_SECRET+x}\" ]"])
            .env("SECENV_TEST_SEALED_SECRET", "must-not-leak");

        executor.configure_env(&mut child)?;
        assert!(child.spawn()?.wait().await?.success());
        Ok(())
    }

    #[tokio::test]
    async fn only_explicit_profile_values_can_reintroduce_secret_sources() -> Result<()> {
        let command = args::ChildCommand::new("sh".to_string(), vec![])?;
        let keep_env_vars = None;
        let secret_source_env_vars = vec!["SECENV_TEST_SEALED_SECRET".to_string()];
        let mut environment = Environment::default();
        environment.insert("SECENV_TEST_SEALED_SECRET".to_string(), "from-env-source".to_string())?;
        environment.remove_secret_sources(&secret_source_env_vars);

        let executor = CommandExecutor::new(&command, &environment, &keep_env_vars, &secret_source_env_vars);
        let mut child = tokio::process::Command::new("sh");
        child
            .args(["-c", "[ -z \"${SECENV_TEST_SEALED_SECRET+x}\" ]"])
            .env("SECENV_TEST_SEALED_SECRET", "inherited");
        executor.configure_env(&mut child)?;
        assert!(child.spawn()?.wait().await?.success());

        environment.insert("SECENV_TEST_SEALED_SECRET".to_string(), "explicit".to_string())?;
        let executor = CommandExecutor::new(&command, &environment, &keep_env_vars, &secret_source_env_vars);
        let mut child = tokio::process::Command::new("sh");
        child.args(["-c", "[ \"$SECENV_TEST_SEALED_SECRET\" = explicit ]"]);
        executor.configure_env(&mut child)?;
        assert!(child.spawn()?.wait().await?.success());
        Ok(())
    }
}
