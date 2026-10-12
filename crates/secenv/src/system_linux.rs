//! Current-user authentication on Linux.
//!
//! Callers pass a reason and receive success or failure. A password, when the
//! stack asks for one, is read from the terminal and is not accepted on stdin.

use {
    anyhow::{
        Context,
        Result,
    },
    pam_client::{
        Context as PamContext,
        ConversationHandler,
        ErrorCode,
        Flag,
    },
    std::{
        ffi::{
            CStr,
            CString,
        },
        fs::OpenOptions,
        io::{
            BufRead,
            BufReader,
            Write,
        },
    },
    zeroize::Zeroize,
};

/// The `sudo` service is used because distributions commonly attach both
/// `pam_unix` and `pam_fprintd` there. Fingerprint is offered only when that
/// stack is configured for it.
const SERVICE: &str = "sudo";

/// Authenticate the current user through the system PAM stack.
///
/// This does not open a login session.
pub(crate) fn authenticate(reason: &str) -> Result<()> {
    if reason.is_empty() {
        anyhow::bail!("System authentication reason must not be empty");
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("System authentication requires a terminal")?;
    let username = whoami::fallible::username().context("Failed to resolve the current user")?;
    eprintln!("secenv is trying to {reason}");

    let mut context = PamContext::new(SERVICE, Some(username.as_str()), TerminalConversation { username })
        .context("Failed to start system authentication")?;
    context
        .authenticate(Flag::DISALLOW_NULL_AUTHTOK)
        .context("System authentication failed")?;
    context
        .acct_mgmt(Flag::DISALLOW_NULL_AUTHTOK)
        .context("System authentication rejected the current account")?;
    Ok(())
}

struct TerminalConversation {
    username: String,
}

impl ConversationHandler for TerminalConversation {
    fn prompt_echo_on(&mut self, prompt: &CStr) -> Result<CString, ErrorCode> {
        let prompt = prompt.to_string_lossy();
        if is_username_prompt(&prompt) {
            return cstring(self.username.as_str());
        }
        self.read_tty(&prompt, false)
    }

    fn prompt_echo_off(&mut self, prompt: &CStr) -> Result<CString, ErrorCode> {
        self.read_tty(&prompt.to_string_lossy(), true)
    }

    fn text_info(&mut self, message: &CStr) {
        eprintln!("{}", message.to_string_lossy());
    }

    fn error_msg(&mut self, message: &CStr) {
        eprintln!("{}", message.to_string_lossy());
    }
}

impl TerminalConversation {
    fn read_tty(&self, prompt: &str, hidden: bool) -> Result<CString, ErrorCode> {
        let mut value = if hidden {
            rpassword::prompt_password(prompt).map_err(|_| ErrorCode::CONV_ERR)?
        } else {
            eprint!("{prompt}");
            let _ = std::io::stderr().flush();
            let tty = OpenOptions::new()
                .read(true)
                .open("/dev/tty")
                .map_err(|_| ErrorCode::CONV_ERR)?;
            let mut line = String::new();
            BufReader::new(tty)
                .read_line(&mut line)
                .map_err(|_| ErrorCode::CONV_ERR)?;
            line.trim_end_matches(['\n', '\r']).to_string()
        };
        let encoded = cstring(value.as_str());
        value.zeroize();
        encoded
    }
}

fn is_username_prompt(prompt: &str) -> bool {
    let prompt = prompt.to_ascii_lowercase();
    prompt.contains("login") || prompt.contains("username") || prompt.contains("user name")
}

fn cstring(value: &str) -> Result<CString, ErrorCode> {
    CString::new(value).map_err(|_| ErrorCode::CONV_ERR)
}

#[cfg(test)]
mod tests {
    use super::is_username_prompt;

    #[test]
    fn username_prompts_are_not_asked_again() {
        assert!(is_username_prompt("login: "));
        assert!(is_username_prompt("Username: "));
        assert!(!is_username_prompt("Password: "));
    }
}
