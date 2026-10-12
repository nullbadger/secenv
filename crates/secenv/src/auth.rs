//! Optional gates evaluated before a profile is unlocked or sealed.
//!
//! `system` asks macOS to authenticate the current user with biometrics or
//! their password. That password is never read by this process. `password` is a
//! separate Argon2id verifier; it must be supplied for that invocation and is
//! not stored.

use {
    anyhow::{
        Context,
        Result,
    },
    argon2::{
        password_hash::{
            rand_core::OsRng,
            PasswordHash,
            PasswordHasher,
            PasswordVerifier,
            SaltString,
        },
        Argon2,
        ARGON2ID_IDENT,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    std::fmt,
    zeroize::Zeroizing,
};

const MIN_MEMORY_KIB: u32 = 19 * 1024;
const MIN_ITERATIONS: u32 = 2;
const MIN_PARALLELISM: u32 = 1;
const HASH_LEN: usize = 32;
const ARGON2_VERSION: u32 = 19;
const MAX_PASSWORD_LEN: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileOperation {
    Unlock,
    Seal,
}

impl ProfileOperation {
    fn verb(self) -> &'static str {
        match self {
            | Self::Unlock => "unlock",
            | Self::Seal => "seal",
        }
    }
}

/// Per-profile authentication requirements. Either field may be set alone.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct ProfileAuth {
    /// Require a fresh macOS prompt for the current user's biometrics or
    /// password.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) system: bool,

    /// Argon2id verifier from `secenv auth password`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) password: Option<ProfilePasswordVerifier>,
}

impl ProfileAuth {
    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(password) = &self.password {
            password.validate_encoded().context("Invalid auth.password verifier")?;
        }
        Ok(())
    }
}

/// Argon2id PHC verifier. The password itself is never stored.
#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct ProfilePasswordVerifier(String);

impl fmt::Debug for ProfilePasswordVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProfilePasswordVerifier(<redacted>)")
    }
}

impl From<ProfilePasswordVerifier> for String {
    fn from(value: ProfilePasswordVerifier) -> Self {
        value.0
    }
}

impl TryFrom<String> for ProfilePasswordVerifier {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        let verifier = Self(value);
        verifier.validate_encoded()?;
        Ok(verifier)
    }
}

impl ProfilePasswordVerifier {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn generate(password: &str) -> Result<Self> {
        validate_plaintext(password)?;
        let salt = SaltString::generate(&mut OsRng);
        let encoded = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|error| anyhow::anyhow!("Failed to hash profile password: {error}"))?
            .to_string();
        Self::try_from(encoded)
    }

    /// Prompt twice on the terminal and print nothing. The caller writes the
    /// verifier.
    pub(crate) fn prompt_new() -> Result<Self> {
        let password = prompt("Enter a new profile password: ")?;
        let confirmation = prompt("Confirm profile password: ")?;
        if !passwords_match(password.as_str(), confirmation.as_str()) {
            anyhow::bail!("Passwords do not match");
        }
        Self::generate(password.as_str())
    }

    pub(crate) fn verify(&self, password: &str) -> Result<()> {
        validate_plaintext(password)?;
        let parsed = self.validate_encoded()?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_error| anyhow::anyhow!("Incorrect profile password"))?;
        Ok(())
    }

    fn validate_encoded(&self) -> Result<PasswordHash<'_>> {
        let parsed = PasswordHash::new(&self.0)
            .map_err(|_error| anyhow::anyhow!("Profile password verifier must be an Argon2id PHC string"))?;
        if parsed.algorithm != ARGON2ID_IDENT {
            anyhow::bail!("Profile password verifier must use Argon2id");
        }
        if parsed.version != Some(ARGON2_VERSION) {
            anyhow::bail!("Profile password verifier must use Argon2id version 19");
        }
        if parsed.params.get("keyid").is_some() || parsed.params.get("data").is_some() {
            anyhow::bail!("Profile password verifier must not include keyid or data parameters");
        }
        let memory = parsed
            .params
            .get_decimal("m")
            .context("Profile password verifier is missing its memory parameter")?;
        let iterations = parsed
            .params
            .get_decimal("t")
            .context("Profile password verifier is missing its iteration parameter")?;
        let parallelism = parsed
            .params
            .get_decimal("p")
            .context("Profile password verifier is missing its parallelism parameter")?;
        if memory < MIN_MEMORY_KIB || iterations < MIN_ITERATIONS || parallelism < MIN_PARALLELISM {
            anyhow::bail!(
                "Profile password verifier is too weak; require at least {MIN_MEMORY_KIB} KiB, {MIN_ITERATIONS} \
                 iterations, and {MIN_PARALLELISM} lane"
            );
        }
        let hash = parsed.hash.context("Profile password verifier is missing a hash")?;
        if hash.len() != HASH_LEN {
            anyhow::bail!("Profile password verifier must be {HASH_LEN} bytes");
        }
        if parsed.salt.is_none() {
            anyhow::bail!("Profile password verifier is missing a salt");
        }
        Ok(parsed)
    }
}

pub(crate) struct ProfileGate<'a> {
    profile_name: &'a str,
    auth: Option<&'a ProfileAuth>,
}

impl<'a> ProfileGate<'a> {
    pub(crate) fn new(profile_name: &'a str, auth: Option<&'a ProfileAuth>) -> Self {
        Self { profile_name, auth }
    }

    /// System authentication runs before the profile password so a
    /// cancelled system prompt does not ask for the profile secret. A
    /// supplied password is rejected when the profile has no verifier,
    /// rather than ignored.
    pub(crate) fn enforce(
        &self,
        operation: ProfileOperation,
        supplied_password: Option<Zeroizing<String>>,
    ) -> Result<()> {
        let requires_password = self.auth.is_some_and(|auth| auth.password.is_some());
        if supplied_password.is_some() && !requires_password {
            anyhow::bail!("Profile '{}' does not require a password", self.profile_name);
        }
        if self.auth.is_some_and(|auth| auth.system) {
            SystemCheck::authenticate(self.profile_name, operation)?;
        }
        if let Some(verifier) = self.auth.and_then(|auth| auth.password.as_ref()) {
            let password = match supplied_password {
                | Some(password) => password,
                | None => prompt(&format!("Enter password for profile '{}': ", self.profile_name))?,
            };
            verifier
                .verify(password.as_str())
                .with_context(|| format!("Profile '{}' rejected the supplied password", self.profile_name))?;
        }
        Ok(())
    }
}

fn prompt(prompt_text: &str) -> Result<Zeroizing<String>> {
    let password = rpassword::prompt_password(prompt_text)
        .context("Failed to read the profile password. Pass --password when no terminal is available")?;
    let password = Zeroizing::new(password);
    validate_plaintext(password.as_str())?;
    Ok(password)
}

fn validate_plaintext(password: &str) -> Result<()> {
    if password.is_empty() {
        anyhow::bail!("Profile password must not be empty");
    }
    if password.len() > MAX_PASSWORD_LEN {
        anyhow::bail!("Profile password must be at most {MAX_PASSWORD_LEN} bytes");
    }
    Ok(())
}

fn passwords_match(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut mismatch = left.len() ^ right.len();
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        mismatch |= usize::from(left_byte ^ right_byte);
    }
    mismatch == 0
}

/// Reason shown by macOS as "<app> is trying to <reason>". Control characters
/// are omitted so a profile name cannot spoof the system dialog.
pub(crate) fn localized_reason(profile_name: &str, operation: ProfileOperation) -> String {
    if is_dialog_safe(profile_name) {
        format!("{} profile {profile_name}", operation.verb())
    } else {
        format!("{} a secenv profile", operation.verb())
    }
}

fn is_dialog_safe(profile_name: &str) -> bool {
    !profile_name.is_empty()
        && profile_name.len() <= 64
        && profile_name.chars().all(|character| !character.is_control())
}

struct SystemCheck;

impl SystemCheck {
    fn authenticate(profile_name: &str, operation: ProfileOperation) -> Result<()> {
        // Platform crates own the prompt. This stays before the first await so the
        // macOS dialog runs on the process main thread.
        system::authenticate(&localized_reason(profile_name, operation))
            .with_context(|| format!("Profile '{profile_name}' requires system authentication"))
    }
}

#[cfg(target_os = "macos")]
mod system {
    use anyhow::Result;

    pub(super) fn authenticate(reason: &str) -> Result<()> {
        secenv_system_macos::authenticate(reason)
    }
}

#[cfg(target_os = "linux")]
mod system {
    use anyhow::Result;

    pub(super) fn authenticate(reason: &str) -> Result<()> {
        secenv_system_linux::authenticate(reason)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod system {
    use anyhow::Result;

    pub(super) fn authenticate(_reason: &str) -> Result<()> {
        anyhow::bail!("System authentication is only available on macOS and Linux");
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        argon2::{
            Algorithm,
            Params,
            Version,
        },
    };

    #[test]
    fn verifier_accepts_the_password_that_created_it_and_rejects_others() -> Result<()> {
        let verifier = ProfilePasswordVerifier::generate("correct horse battery staple")?;
        assert!(verifier.as_str().starts_with("$argon2id$v=19$"));
        verifier.verify("correct horse battery staple")?;
        assert!(verifier.verify("wrong password").is_err());
        assert!(verifier.verify("").is_err());

        let again = ProfilePasswordVerifier::generate("correct horse battery staple")?;
        assert_ne!(verifier.as_str(), again.as_str());
        Ok(())
    }

    #[test]
    fn verifier_rejects_weak_or_malformed_encodings() {
        assert!(ProfilePasswordVerifier::try_from("not-a-verifier".to_string()).is_err());

        let params = Params::new(8 * 1024, 1, 1, Some(HASH_LEN)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let weak = argon2.hash_password(b"password", &salt).unwrap().to_string();
        let error = ProfilePasswordVerifier::try_from(weak).unwrap_err();
        assert!(error.to_string().contains("too weak"), "{error}");
    }

    #[test]
    fn gate_requires_each_check_only_when_configured() -> Result<()> {
        ProfileGate::new("default", None).enforce(ProfileOperation::Unlock, None)?;
        let error = ProfileGate::new("default", None)
            .enforce(ProfileOperation::Seal, Some(Zeroizing::new("secret".to_string())))
            .unwrap_err();
        assert!(error.to_string().contains("does not require a password"), "{error}");

        let auth = ProfileAuth {
            system: false,
            password: Some(ProfilePasswordVerifier::generate("profile-secret")?),
        };
        ProfileGate::new("production", Some(&auth)).enforce(
            ProfileOperation::Unlock,
            Some(Zeroizing::new("profile-secret".to_string())),
        )?;
        let rejected = ProfileGate::new("production", Some(&auth))
            .enforce(ProfileOperation::Seal, Some(Zeroizing::new("nope".to_string())))
            .unwrap_err();
        assert!(
            rejected.to_string().contains("rejected the supplied password"),
            "{rejected}"
        );
        Ok(())
    }

    #[test]
    fn localized_reason_drops_control_characters() {
        assert_eq!(
            localized_reason("production", ProfileOperation::Unlock),
            "unlock profile production"
        );
        assert_eq!(
            localized_reason("prod\nuction", ProfileOperation::Seal),
            "seal a secenv profile"
        );
        assert_eq!(
            localized_reason(&"x".repeat(65), ProfileOperation::Unlock),
            "unlock a secenv profile"
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn system_requirement_fails_closed_without_a_platform_crate() {
        let auth = ProfileAuth {
            system: true,
            password: None,
        };
        let error = ProfileGate::new("production", Some(&auth))
            .enforce(ProfileOperation::Unlock, None)
            .unwrap_err();
        assert!(
            error.to_string().contains("only available on macOS and Linux"),
            "{error}"
        );
    }
}
