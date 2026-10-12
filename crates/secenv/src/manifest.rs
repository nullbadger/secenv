use {
    crate::{
        auth::ProfileAuth,
        aws::{
            AwsSecretManager,
            AwsSecretSpec,
        },
        gcp::{
            GcpSecretManager,
            GcpSecretSpec,
        },
        gpg::{
            GpgKeySpec,
            GpgManager,
        },
        sealed::ResolvedSealedSecret,
    },
    anyhow::{
        Context,
        Result,
    },
    base64::Engine,
    hocon::HoconLoader,
    semver::Version,
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        collections::HashMap,
        fmt,
        path::PathBuf,
    },
    zeroize::Zeroizing,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EncodedValue {
    Literal(String),
    Base64(String),
}

impl fmt::Debug for EncodedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | EncodedValue::Literal(_) => f.write_str("Literal(<redacted>)"),
            | EncodedValue::Base64(_) => f.write_str("Base64(<redacted>)"),
        }
    }
}

impl EncodedValue {
    pub(crate) fn decode(&self) -> Result<String> {
        match self {
            | EncodedValue::Literal(value) => Ok(value.clone()),
            | EncodedValue::Base64(value) => {
                let decoded_bytes = base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .context("Failed to decode base64 value")?;

                Ok(String::from_utf8(decoded_bytes).context("Decoded value is not valid UTF-8")?)
            },
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct EncodedValueWrapper {
    #[serde(flatten)]
    pub(crate) inner: EncodedValue,
}

impl fmt::Debug for EncodedValueWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodedValueWrapper")
            .field("inner", &self.inner)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SecretAllocation {
    Literal(EncodedValue),
    File(String),
    Env(String),
    Gpg {
        fingerprint: String,
    },
    Gcp {
        secret: String,
        version: Option<String>,
    },
    Aws {
        secret: String,
        version: Option<String>,
        region: Option<String>,
    },
}

impl fmt::Debug for SecretAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | SecretAllocation::Literal(_) => f.write_str("Literal(<redacted>)"),
            | SecretAllocation::File(path) => write!(f, "File({})", path),
            | SecretAllocation::Env(variable) => write!(f, "Env(variable={})", variable),
            | SecretAllocation::Gpg { fingerprint } => write!(f, "Gpg(fingerprint={})", fingerprint),
            | SecretAllocation::Gcp { secret, .. } => write!(f, "Gcp(secret={})", secret),
            | SecretAllocation::Aws { secret, .. } => write!(f, "Aws(secret={})", secret),
        }
    }
}

impl SecretAllocation {
    pub(crate) fn resolve(&self, removed_env_vars: &[String]) -> Result<String> {
        match self {
            | SecretAllocation::Literal(encoded_value) => encoded_value.decode(),
            | SecretAllocation::File(file_path) => {
                std::fs::read_to_string(file_path).context(format!("Failed to read file: {}", file_path))
            },
            | SecretAllocation::Env(variable) => {
                Self::resolve_environment_variable_with(variable, |name| std::env::var(name))
            },
            | SecretAllocation::Gpg { fingerprint } => {
                let spec = GpgKeySpec::new(fingerprint.clone())?;
                GpgManager
                    .export_private_key(&spec, removed_env_vars)
                    .context("Failed to export GPG private key")
            },
            | SecretAllocation::Gcp { secret, version } => {
                let spec = GcpSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                };
                GcpSecretManager
                    .access_secret(&spec, removed_env_vars)
                    .context("Failed to access GCP secret")
            },
            | SecretAllocation::Aws {
                secret,
                version,
                region,
            } => {
                let spec = AwsSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                    region: region.clone(),
                };
                AwsSecretManager
                    .access_secret(&spec, removed_env_vars)
                    .context("Failed to access AWS secret")
            },
        }
    }

    pub(crate) fn environment_variable(&self) -> Option<&str> {
        match self {
            | Self::Env(variable) => Some(variable),
            | Self::Literal(_) | Self::File(_) | Self::Gpg { .. } | Self::Gcp { .. } | Self::Aws { .. } => None,
        }
    }

    fn resolve_environment_variable_with<F>(variable: &str, lookup: F) -> Result<String>
    where F: FnOnce(&str) -> std::result::Result<String, std::env::VarError> {
        if variable.is_empty() || variable.contains('=') || variable.contains('\0') {
            anyhow::bail!("Invalid environment variable name for secret source");
        }
        match lookup(variable) {
            | Ok(value) => Ok(value),
            | Err(std::env::VarError::NotPresent) => {
                anyhow::bail!("Environment variable '{}' is not set", variable)
            },
            | Err(std::env::VarError::NotUnicode(_)) => {
                anyhow::bail!("Environment variable '{}' is not valid Unicode", variable)
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct SecretAllocationWrapper {
    #[serde(flatten)]
    pub(crate) inner: SecretAllocation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Secret {
    #[serde(rename = "pgp")]
    Pgp(SecretAllocationWrapper),
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Secret::Pgp(alloc) => write!(f, "Pgp({:?})", alloc),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct SecretWrapper {
    #[serde(flatten)]
    pub(crate) inner: Secret,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct Manifest {
    pub(crate) version: String,
    #[serde(skip)]
    source_path: PathBuf,
    #[serde(default)]
    pub(crate) profiles: HashMap<String, ManifestProfile>,
}

impl fmt::Debug for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manifest")
            .field("version", &self.version)
            .field("source_path", &self.source_path)
            .field("profiles", &format!("[{} profile(s)]", self.profiles.len()))
            .finish()
    }
}

impl Manifest {
    pub(crate) fn load(source_path: PathBuf) -> Result<Self> {
        let content = Zeroizing::new(
            std::fs::read_to_string(&source_path)
                .with_context(|| format!("Failed to read config file: {}", source_path.display()))?,
        );
        let mut manifest: Self = HoconLoader::new()
            .no_system()
            .strict()
            .load_str(&content)
            .with_context(|| format!("Failed to parse HOCON config: {}", source_path.display()))?
            .resolve()
            .with_context(|| format!("Failed to deserialize HOCON config: {}", source_path.display()))?;
        manifest.source_path = source_path;
        manifest.validate_version()?;
        manifest.validate_profiles()?;
        Ok(manifest)
    }

    pub(crate) fn source_directory(&self) -> Result<PathBuf> {
        self.source_path
            .parent()
            .map(PathBuf::from)
            .with_context(|| format!("Config file '{}' has no parent directory", self.source_path.display()))
    }

    pub(crate) fn validate_version(&self) -> Result<()> {
        let cli_version = Version::parse(env!("CARGO_PKG_VERSION")).context("Failed to parse CLI version")?;

        #[cfg(debug_assertions)]
        if env!("CARGO_PKG_VERSION") == "0.0.0" {
            return Ok(());
        }

        let config_version =
            Version::parse(&self.version).context(format!("Invalid version format in config: '{}'", self.version))?;

        if config_version.major != cli_version.major {
            return Err(anyhow::anyhow!(
                "Config version {} is incompatible with CLI version {}. Major version mismatch.",
                config_version,
                cli_version
            ));
        }

        if config_version > cli_version {
            return Err(anyhow::anyhow!(
                "Config version {} is newer than CLI version {}. Please upgrade the CLI.",
                config_version,
                cli_version
            ));
        }

        Ok(())
    }

    fn validate_profiles(&self) -> Result<()> {
        for (profile_name, profile) in &self.profiles {
            profile
                .validate()
                .with_context(|| format!("Invalid profile '{}'", profile_name))?;
        }
        Ok(())
    }

    /// Warn if the config file has insecure permissions (group/world-writable).
    #[cfg(unix)]
    pub(crate) fn warn_if_insecure_permissions(&self) {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(&self.source_path) {
            let mode = meta.mode();
            if mode & 0o002 != 0 {
                eprintln!(
                    "WARNING: Config file '{}' is world-writable (mode {:04o}). This is a security risk.",
                    self.source_path.display(),
                    mode & 0o777
                );
            }
            if mode & 0o020 != 0 {
                eprintln!(
                    "WARNING: Config file '{}' is group-writable (mode {:04o}). This may be a security risk.",
                    self.source_path.display(),
                    mode & 0o777
                );
            }
        }
    }

    #[cfg(not(unix))]
    pub(crate) fn warn_if_insecure_permissions(&self) {}

    /// Build an example manifest suitable for `init`.
    pub(crate) fn example(source_path: PathBuf) -> Self {
        let mut vars = HashMap::new();

        vars.insert("APP_NAME".to_string(), ContentWrapper {
            inner: Content::Plain(EncodedValue::Literal("myapp".to_string())),
        });

        vars.insert("DB_HOST_EXAMPLE".to_string(), ContentWrapper {
            inner: Content::Plain(EncodedValue::Base64("bG9jYWxob3N0".to_string())),
        });

        vars.insert("SECRET_TOKEN_EXAMPLE".to_string(), ContentWrapper {
            inner: Content::Secure {
                secret: SecretWrapper {
                    inner: Secret::Pgp(SecretAllocationWrapper {
                        inner: SecretAllocation::File("/path/to/private.key".to_string()),
                    }),
                },
                value: EncodedValueWrapper {
                    inner: EncodedValue::Literal("-----BEGIN PGP MESSAGE-----...".to_string()),
                },
            },
        });

        vars.insert("API_KEY_EXAMPLE".to_string(), ContentWrapper {
            inner: Content::Secure {
                secret: SecretWrapper {
                    inner: Secret::Pgp(SecretAllocationWrapper {
                        inner: SecretAllocation::Gcp {
                            secret: "projects/myproject/secrets/my-pgp-key".to_string(),
                            version: Some("latest".to_string()),
                        },
                    }),
                },
                value: EncodedValueWrapper {
                    inner: EncodedValue::Base64("<base64-encoded-ASCII-armored-message>".to_string()),
                },
            },
        });

        vars.insert("GPG_ENCRYPTED_EXAMPLE".to_string(), ContentWrapper {
            inner: Content::Secure {
                secret: SecretWrapper {
                    inner: Secret::Pgp(SecretAllocationWrapper {
                        inner: SecretAllocation::Gpg {
                            fingerprint: "1E1BAC706C352094D490D5393F5167F1F3002043".to_string(),
                        },
                    }),
                },
                value: EncodedValueWrapper {
                    inner: EncodedValue::Base64("<base64-encoded-ASCII-armored-message>".to_string()),
                },
            },
        });

        let mut files = HashMap::new();

        files.insert("./config.json".to_string(), ContentWrapper {
            inner: Content::Plain(EncodedValue::Literal("{\"key\": \"value\"}".to_string())),
        });

        files.insert("./credentials.key".to_string(), ContentWrapper {
            inner: Content::Secure {
                secret: SecretWrapper {
                    inner: Secret::Pgp(SecretAllocationWrapper {
                        inner: SecretAllocation::File("/path/to/private.key".to_string()),
                    }),
                },
                value: EncodedValueWrapper {
                    inner: EncodedValue::Literal("-----BEGIN PGP MESSAGE-----...".to_string()),
                },
            },
        });

        files.insert("./aws-certificate.pem".to_string(), ContentWrapper {
            inner: Content::Aws {
                secret: "my-app/certificates/tls-cert".to_string(),
                version: None,
                region: Some("us-east-1".to_string()),
            },
        });

        files.insert("./gcs-certificate.pem".to_string(), ContentWrapper {
            inner: Content::Gcs {
                secret: "projects/myproject/secrets/tls-cert".to_string(),
                version: Some("latest".to_string()),
            },
        });

        let default_profile = ManifestProfile {
            auth: None,
            sealed: None,
            files,
            env: ManifestEnv {
                keep: Some(vec!["^PATH$".to_string(), "^LC_.*".to_string()]),
                vars,
                from: vec![FromLocationWrapper {
                    inner: FromLocation::Gcs {
                        secret: "projects/myproject/secrets/my-gcs-secret".to_string(),
                        version: Some("latest".to_string()),
                    },
                }],
            },
        };

        let mut profiles = HashMap::new();
        profiles.insert("default".to_string(), default_profile);

        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            source_path,
            profiles,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct ManifestProfile {
    /// Optional system and profile-password gates. Absent means neither
    /// is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) auth: Option<ProfileAuth>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sealed: Option<SealedFiles>,

    #[serde(default)]
    pub(crate) files: HashMap<String, ContentWrapper>,

    #[serde(default)]
    pub(crate) env: ManifestEnv,
}

impl ManifestProfile {
    fn validate(&self) -> Result<()> {
        if let Some(auth) = &self.auth {
            auth.validate()?;
        }
        for (path, content) in &self.files {
            if matches!(&content.inner, Content::Sealed { .. }) {
                anyhow::bail!(
                    "Temporary file '{}' uses sealed inline content, which is supported only in profile environment \
                     variables",
                    path
                );
            }
        }
        Ok(())
    }

    pub(crate) fn secret_environment_variables(&self) -> impl Iterator<Item=&str> {
        self.sealed
            .iter()
            .flat_map(SealedFiles::environment_variables)
            .chain(
                self.files
                    .values()
                    .filter_map(ContentWrapper::secret_environment_variable),
            )
            .chain(
                self.env
                    .vars
                    .values()
                    .filter_map(ContentWrapper::secret_environment_variable),
            )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct SealedFiles {
    /// HOCON or JSON files replaced with their decrypted form for the command
    /// lifetime, then restored.
    #[serde(default)]
    pub(crate) files: HashMap<String, SealedFile>,

    /// Temporary output path to encrypted template path.
    #[serde(default)]
    pub(crate) templates: HashMap<String, SealedTemplate>,
}

impl SealedFiles {
    pub(crate) fn environment_variables(&self) -> impl Iterator<Item=&str> {
        self.files
            .values()
            .map(|file| &file.secret)
            .chain(self.templates.values().map(|template| &template.secret))
            .filter_map(SealedSecretWrapper::environment_variable)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SealedSecret {
    Pgp(SecretAllocationWrapper),
    Argon2idXchacha20Poly1305(SecretAllocationWrapper),
}

impl fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Self::Pgp(allocation) => write!(f, "Pgp({:?})", allocation),
            | Self::Argon2idXchacha20Poly1305(allocation) => {
                write!(f, "Argon2idXchacha20Poly1305({:?})", allocation)
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct SealedSecretWrapper {
    #[serde(flatten)]
    pub(crate) inner: SealedSecret,
}

impl SealedSecretWrapper {
    fn environment_variable(&self) -> Option<&str> {
        match &self.inner {
            | SealedSecret::Pgp(allocation) | SealedSecret::Argon2idXchacha20Poly1305(allocation) => {
                allocation.inner.environment_variable()
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct SealedFile {
    pub(crate) secret: SealedSecretWrapper,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct SealedTemplate {
    pub(crate) source: String,
    pub(crate) secret: SealedSecretWrapper,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FromLocation {
    File(String),
    #[serde(rename = "gcs")]
    Gcs {
        secret: String,
        version: Option<String>,
    },
    #[serde(rename = "aws")]
    Aws {
        secret: String,
        version: Option<String>,
        region: Option<String>,
    },
}

impl fmt::Debug for FromLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | FromLocation::File(path) => write!(f, "File({})", path),
            | FromLocation::Gcs { secret, .. } => write!(f, "Gcs({})", secret),
            | FromLocation::Aws { secret, .. } => write!(f, "Aws({})", secret),
        }
    }
}

impl FromLocation {
    /// Fetch the raw string content from this source.
    pub(crate) fn resolve(&self, removed_env_vars: &[String]) -> Result<String> {
        match self {
            | FromLocation::Gcs { secret, version } => {
                let spec = GcpSecretSpec {
                    secret: secret.to_string(),
                    version: version.as_ref().map(|v| v.to_string()),
                };
                GcpSecretManager.access_secret(&spec, removed_env_vars)
            },
            | FromLocation::Aws {
                secret,
                version,
                region,
            } => {
                let spec = AwsSecretSpec {
                    secret: secret.to_string(),
                    version: version.as_ref().map(|v| v.to_string()),
                    region: region.as_ref().map(|r| r.to_string()),
                };
                AwsSecretManager.access_secret(&spec, removed_env_vars)
            },
            | FromLocation::File(file_path) => {
                std::fs::read_to_string(file_path).context(format!("Failed to read env file: {}", file_path))
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct FromLocationWrapper {
    #[serde(flatten)]
    pub(crate) inner: FromLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) struct ManifestEnv {
    #[serde(default)]
    pub(crate) keep: Option<Vec<String>>,

    #[serde(default)]
    pub(crate) vars: HashMap<String, ContentWrapper>,

    #[serde(default)]
    pub(crate) from: Vec<FromLocationWrapper>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Content {
    Plain(EncodedValue),

    Secure {
        secret: SecretWrapper,
        value: EncodedValueWrapper,
    },

    Sealed {
        secret: SealedSecretWrapper,
        value: String,
    },

    /// Load content directly from a local file
    File(String),

    /// Load content directly from GCP Secret Manager
    #[serde(rename = "gcs")]
    Gcs {
        secret: String,
        version: Option<String>,
    },

    /// Load content directly from AWS Secrets Manager
    #[serde(rename = "aws")]
    Aws {
        secret: String,
        version: Option<String>,
        region: Option<String>,
    },
}

impl fmt::Debug for Content {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Content::Plain(_) => f.write_str("Plain(<redacted>)"),
            | Content::Secure { secret, .. } => write!(f, "Secure({:?})", secret),
            | Content::Sealed { secret, .. } => write!(f, "Sealed({:?})", secret),
            | Content::File(path) => write!(f, "File({})", path),
            | Content::Gcs { secret, .. } => write!(f, "Gcs({})", secret),
            | Content::Aws { secret, .. } => write!(f, "Aws({})", secret),
        }
    }
}

impl Content {
    pub(crate) fn resolve(
        &self,
        pgp_manager: &mut crate::pgp::PgpManager,
        removed_env_vars: &[String],
    ) -> Result<String> {
        match self {
            | Content::Plain(encoded_value) => encoded_value.decode(),
            | Content::Secure { secret, value } => {
                let encrypted_data = value.inner.decode()?;

                match &secret.inner {
                    | Secret::Pgp(allocation_wrapper) => {
                        match &allocation_wrapper.inner {
                            | SecretAllocation::Gpg { fingerprint } => {
                                let spec = GpgKeySpec::new(fingerprint.clone())?;
                                GpgManager
                                    .decrypt_data(&spec, &encrypted_data, removed_env_vars)
                                    .context("Failed to decrypt value with GPG")
                            },
                            | _ => {
                                let pgp_key = Zeroizing::new(allocation_wrapper.inner.resolve(removed_env_vars)?);
                                pgp_manager
                                    .decrypt(pgp_key.as_str(), &encrypted_data)
                                    .context("Failed to decrypt value with PGP key")
                            },
                        }
                    },
                }
            },
            | Content::Sealed { secret, value } => {
                ResolvedSealedSecret::load(secret, removed_env_vars)?.open_marker(value, pgp_manager)
            },
            | Content::File(file_path) => {
                std::fs::read_to_string(file_path).context(format!("Failed to read file: {}", file_path))
            },
            | Content::Gcs { secret, version } => {
                let spec = GcpSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                };
                GcpSecretManager
                    .access_secret(&spec, removed_env_vars)
                    .context("Failed to access GCP secret")
            },
            | Content::Aws {
                secret,
                version,
                region,
            } => {
                let spec = AwsSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                    region: region.clone(),
                };
                AwsSecretManager
                    .access_secret(&spec, removed_env_vars)
                    .context("Failed to access AWS secret")
            },
        }
    }

    pub(crate) fn seal(
        &self,
        plaintext: &str,
        pgp_manager: &crate::pgp::PgpManager,
        removed_env_vars: &[String],
    ) -> Result<String> {
        let Self::Sealed { secret, .. } = self else {
            anyhow::bail!("Environment variable is not configured as a sealed value");
        };
        ResolvedSealedSecret::load(secret, removed_env_vars)?.seal_marker(plaintext, pgp_manager)
    }

    pub(crate) fn resolve_temporary_file(
        &self,
        pgp_manager: &mut crate::pgp::PgpManager,
        removed_env_vars: &[String],
    ) -> Result<String> {
        if matches!(self, Self::Sealed { .. }) {
            anyhow::bail!("Sealed inline content is supported only for profile environment variables");
        }
        self.resolve(pgp_manager, removed_env_vars)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct ContentWrapper {
    #[serde(flatten)]
    pub(crate) inner: Content,
}

impl ContentWrapper {
    fn secret_environment_variable(&self) -> Option<&str> {
        match &self.inner {
            | Content::Secure { secret, .. } => {
                match &secret.inner {
                    | Secret::Pgp(allocation) => allocation.inner.environment_variable(),
                }
            },
            | Content::Sealed { secret, .. } => secret.environment_variable(),
            | Content::Plain(_) | Content::File(_) | Content::Gcs { .. } | Content::Aws { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_profiles_remain_compatible() -> Result<()> {
        let manifest: Manifest = hocon::de::from_str(
            r#"
            version = "0.0.0"
            profiles.default.env.vars.APP_NAME.plain.literal = "myapp"
            "#,
        )?;

        let profile = manifest.profiles.get("default").context("Missing default profile")?;
        assert!(profile.sealed.is_none());
        assert!(profile.auth.is_none());
        Ok(())
    }

    #[test]
    fn parses_optional_profile_auth_independently() -> Result<()> {
        let verifier = crate::auth::ProfilePasswordVerifier::generate("profile-secret")?;
        let manifest: Manifest = hocon::de::from_str(&format!(
            r#"
            version = "0.0.0"
            profiles.system_only.auth.system = true
            profiles.password.auth.password = "{}"
            profiles.both.auth {{
              system = true
              password = "{}"
            }}
            "#,
            verifier.as_str(),
            verifier.as_str(),
        ))?;

        let system_only = &manifest.profiles["system_only"]
            .auth
            .as_ref()
            .context("Missing system auth")?;
        assert!(system_only.system);
        assert!(system_only.password.is_none());

        let password = &manifest.profiles["password"]
            .auth
            .as_ref()
            .context("Missing password auth")?;
        assert!(!password.system);
        password
            .password
            .as_ref()
            .context("Missing password verifier")?
            .verify("profile-secret")?;

        let both = &manifest.profiles["both"]
            .auth
            .as_ref()
            .context("Missing combined auth")?;
        assert!(both.system);
        assert!(both.password.is_some());
        Ok(())
    }

    #[test]
    fn rejects_unknown_auth_fields_and_weak_password_verifiers() {
        let unknown = hocon::de::from_str::<Manifest>(
            r#"
            version = "0.0.0"
            profiles.default.auth.touch_id = true
            "#,
        );
        assert!(unknown.is_err(), "unknown auth field should be rejected");

        let weak = hocon::de::from_str::<Manifest>(
            r#"
            version = "0.0.0"
            profiles.default.auth.password = "not-a-verifier"
            "#,
        );
        assert!(weak.is_err(), "malformed password verifier should be rejected");
    }

    #[test]
    fn parses_inline_sealed_profile_environment_values() -> Result<()> {
        let manifest: Manifest = hocon::de::from_str(
            r#"
            version = "0.0.0"
            profiles.default.env.vars {
              API_TOKEN.sealed {
                secret.pgp.gcp.secret = "projects/example/secrets/pgp-key"
                value = "ENC[PGP,Y2lwaGVydGV4dA==]"
              }
              DATABASE_PASSWORD.sealed {
                secret.argon2id_xchacha20_poly1305.env = "SECENV_DATABASE_PASSPHRASE"
                value = "ENC[ARGON2ID-XCHACHA20-POLY1305,Y2lwaGVydGV4dA==]"
              }
            }
            "#,
        )?;

        let vars = &manifest.profiles["default"].env.vars;
        assert!(matches!(vars["API_TOKEN"].inner, Content::Sealed {
            secret: SealedSecretWrapper {
                inner: SealedSecret::Pgp(_),
            },
            ..
        }));
        assert!(matches!(
            &vars["DATABASE_PASSWORD"].inner,
            Content::Sealed {
                secret: SealedSecretWrapper {
                    inner: SealedSecret::Argon2idXchacha20Poly1305(_),
                },
                value,
            } if value.starts_with("ENC[ARGON2ID-XCHACHA20-POLY1305,")
        ));
        Ok(())
    }

    #[test]
    fn seals_and_opens_inline_profile_environment_values() -> Result<()> {
        let secret = SealedSecretWrapper {
            inner: SealedSecret::Argon2idXchacha20Poly1305(SecretAllocationWrapper {
                inner: SecretAllocation::Literal(EncodedValue::Literal("high-entropy-passphrase".to_string())),
            }),
        };
        let placeholder = Content::Sealed {
            secret: secret.clone(),
            value: String::new(),
        };
        let pgp_manager = crate::pgp::PgpManager::default();
        let marker = placeholder.seal("database-password", &pgp_manager, &[])?;
        let content = Content::Sealed {
            secret: secret.clone(),
            value: marker,
        };
        let mut pgp_manager = crate::pgp::PgpManager::default();
        assert_eq!(content.resolve(&mut pgp_manager, &[])?, "database-password");

        let unmarked = Content::Sealed {
            secret: secret.clone(),
            value: "database-password".to_string(),
        };
        assert!(unmarked.resolve(&mut pgp_manager, &[]).is_err());

        let mismatched = Content::Sealed {
            secret,
            value: "ENC[PGP,Y2lwaGVydGV4dA==]".to_string(),
        };
        assert!(format!("{:#}", mismatched.resolve(&mut pgp_manager, &[]).unwrap_err())
            .contains("configured for ARGON2ID-XCHACHA20-POLY1305"));
        assert!(mismatched
            .resolve_temporary_file(&mut pgp_manager, &[])
            .unwrap_err()
            .to_string()
            .contains("only for profile environment variables"));
        Ok(())
    }

    #[test]
    fn rejects_inline_sealed_temporary_files_during_manifest_validation() -> Result<()> {
        let manifest: Manifest = hocon::de::from_str(
            r#"
            version = "0.0.0"
            profiles = {
              default = {
                files = {
                  temporary = {
                    sealed = {
                      secret = {
                        argon2id_xchacha20_poly1305 = {
                          env = "SHOULD_NOT_BE_READ"
                        }
                      }
                      value = "ENC[ARGON2ID-XCHACHA20-POLY1305,Y2lwaGVydGV4dA==]"
                    }
                  }
                }
              }
            }
            "#,
        )?;

        let error = manifest.validate_profiles().unwrap_err();
        let message = format!("{:#}", error);
        assert!(
            message.contains("supported only in profile environment variables"),
            "{message}"
        );
        Ok(())
    }

    #[test]
    fn parses_profile_sealed_files_and_templates() -> Result<()> {
        let manifest: Manifest = hocon::de::from_str(
            r#"
            version = "0.0.0"
            profiles.default.sealed {
              files {
                "./application.conf" {
                  secret.pgp.gcp.secret = "projects/example/secrets/application-pgp-key"
                }
              }
              templates {
                "./credentials.json" {
                  source = "./credentials.json.sealed"
                  secret.argon2id_xchacha20_poly1305.gcp.secret = "projects/example/secrets/credentials-passphrase"
                }
              }
            }
            "#,
        )?;

        let sealed = manifest
            .profiles
            .get("default")
            .and_then(|profile| profile.sealed.as_ref())
            .context("Missing sealed profile configuration")?;
        assert_eq!(
            sealed
                .templates
                .get("./credentials.json")
                .map(|template| template.source.as_str()),
            Some("./credentials.json.sealed")
        );
        assert!(sealed.files.contains_key("./application.conf"));
        assert!(matches!(
            sealed.files["./application.conf"].secret.inner,
            SealedSecret::Pgp(SecretAllocationWrapper {
                inner: SecretAllocation::Gcp { .. }
            })
        ));
        assert!(matches!(
            sealed.templates["./credentials.json"].secret.inner,
            SealedSecret::Argon2idXchacha20Poly1305(SecretAllocationWrapper {
                inner: SecretAllocation::Gcp { .. }
            })
        ));
        Ok(())
    }

    #[test]
    fn parses_environment_sealed_secret_sources() -> Result<()> {
        let manifest: Manifest = hocon::de::from_str(
            r#"
            version = "0.0.0"
            profiles.default.sealed {
              files {
                "./application.conf" {
                  secret.pgp.env = "SECENV_PGP_KEY"
                }
              }
              templates {
                "./credentials.json" {
                  source = "./credentials.json.sealed"
                  secret.argon2id_xchacha20_poly1305.env = "SECENV_PASSWORD"
                }
              }
            }
            "#,
        )?;

        let sealed = manifest.profiles["default"]
            .sealed
            .as_ref()
            .context("Missing sealed configuration")?;
        assert!(matches!(
            &sealed.files["./application.conf"].secret.inner,
            SealedSecret::Pgp(SecretAllocationWrapper {
                inner: SecretAllocation::Env(variable),
            }) if variable == "SECENV_PGP_KEY"
        ));
        assert!(matches!(
            &sealed.templates["./credentials.json"].secret.inner,
            SealedSecret::Argon2idXchacha20Poly1305(SecretAllocationWrapper {
                inner: SecretAllocation::Env(variable),
            }) if variable == "SECENV_PASSWORD"
        ));
        let mut variables = sealed.environment_variables().collect::<Vec<_>>();
        variables.sort_unstable();
        assert_eq!(variables, vec!["SECENV_PASSWORD", "SECENV_PGP_KEY"]);
        Ok(())
    }

    #[test]
    fn collects_environment_sources_across_the_profile() -> Result<()> {
        let manifest: Manifest = hocon::de::from_str(
            r#"
            version = "0.0.0"
            profiles.default {
              sealed.files {
                "./application.conf" {
                  secret.pgp.env = "SECENV_SEALED_KEY"
                }
              }
              files {
                "./temporary.txt" {
                  secure {
                    secret.pgp.env = "SECENV_FILE_KEY"
                    value.literal = "encrypted"
                  }
                }
              }
              env.vars.TOKEN.secure {
                secret.pgp.env = "SECENV_ENV_KEY"
                value.literal = "encrypted"
              }
              env.vars.PASSWORD.sealed {
                secret.argon2id_xchacha20_poly1305.env = "SECENV_PASSWORD_KEY"
                value = "ENC[ARGON2ID-XCHACHA20-POLY1305,Y2lwaGVydGV4dA==]"
              }
            }
            "#,
        )?;

        let mut variables = manifest.profiles["default"]
            .secret_environment_variables()
            .collect::<Vec<_>>();
        variables.sort_unstable();
        assert_eq!(variables, vec![
            "SECENV_ENV_KEY",
            "SECENV_FILE_KEY",
            "SECENV_PASSWORD_KEY",
            "SECENV_SEALED_KEY"
        ]);
        Ok(())
    }

    #[test]
    fn resolves_environment_sealed_secrets_without_exposing_invalid_values() -> Result<()> {
        let value =
            SecretAllocation::resolve_environment_variable_with(
                "SECENV_PASSWORD",
                |_| Ok("test-password".to_string()),
            )?;
        assert_eq!(value, "test-password");

        let missing = SecretAllocation::resolve_environment_variable_with("SECENV_PASSWORD", |_| {
            Err(std::env::VarError::NotPresent)
        })
        .unwrap_err();
        assert_eq!(missing.to_string(), "Environment variable 'SECENV_PASSWORD' is not set");

        let invalid = SecretAllocation::resolve_environment_variable_with("SECENV_PASSWORD", |_| {
            Err(std::env::VarError::NotUnicode(std::ffi::OsString::from("hidden-value")))
        })
        .unwrap_err();
        assert_eq!(
            invalid.to_string(),
            "Environment variable 'SECENV_PASSWORD' is not valid Unicode"
        );
        assert!(!invalid.to_string().contains("hidden-value"));
        Ok(())
    }

    #[test]
    fn parses_local_and_aws_sealed_secret_sources() -> Result<()> {
        let manifest: Manifest = hocon::de::from_str(
            r#"
            version = "0.0.0"
            profiles.default.sealed.files {
              "./literal.conf" {
                secret.pgp.literal.literal = "certificate"
              }
              "./file.conf" {
                secret.argon2id_xchacha20_poly1305.file = "password.txt"
              }
              "./gpg.conf" {
                secret.pgp.gpg.fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
              }
              "./aws.conf" {
                secret.argon2id_xchacha20_poly1305.aws.secret = "application/password"
              }
            }
            "#,
        )?;

        let files = &manifest.profiles["default"]
            .sealed
            .as_ref()
            .context("Missing sealed configuration")?
            .files;
        assert!(matches!(
            files["./literal.conf"].secret.inner,
            SealedSecret::Pgp(SecretAllocationWrapper {
                inner: SecretAllocation::Literal(EncodedValue::Literal(_)),
            })
        ));
        assert!(matches!(
            files["./file.conf"].secret.inner,
            SealedSecret::Argon2idXchacha20Poly1305(SecretAllocationWrapper {
                inner: SecretAllocation::File(_),
            })
        ));
        assert!(matches!(
            files["./gpg.conf"].secret.inner,
            SealedSecret::Pgp(SecretAllocationWrapper {
                inner: SecretAllocation::Gpg { .. },
            })
        ));
        assert!(matches!(
            files["./aws.conf"].secret.inner,
            SealedSecret::Argon2idXchacha20Poly1305(SecretAllocationWrapper {
                inner: SecretAllocation::Aws { .. },
            })
        ));
        Ok(())
    }
}
