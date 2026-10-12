//! Current-user authentication on macOS.
//!
//! Callers pass a reason and receive success or failure. They do not see the
//! account password.

use {
    anyhow::Result,
    block2::RcBlock,
    objc2::runtime::Bool,
    objc2_foundation::{
        NSDate,
        NSDefaultRunLoopMode,
        NSError,
        NSInteger,
        NSRunLoop,
        NSString,
    },
    objc2_local_authentication::{
        kLAErrorAuthenticationFailed,
        kLAErrorBiometryLockout,
        kLAErrorNotInteractive,
        kLAErrorPasscodeNotSet,
        kLAErrorSystemCancel,
        kLAErrorUserCancel,
        kLAErrorUserFallback,
        LAContext,
        LACredentialType,
        LAPolicy,
    },
    std::{
        sync::mpsc,
        time::{
            Duration,
            Instant,
        },
    },
};

/// Current user only: Touch ID or that user's password. The biometrics-only
/// policy is not used, because choosing Enter Password must switch to the
/// password instead of failing. Companion devices are not accepted.
const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthentication;

/// Authenticate the current user with Touch ID or that user's password.
///
/// Must run on the process main thread. An empty reason is rejected because the
/// system dialog requires one. The password never enters this process.
pub(crate) fn authenticate(reason: &str) -> Result<()> {
    if reason.is_empty() {
        anyhow::bail!("System authentication reason must not be empty");
    }
    let context = new_context()?;
    configure(&context, false)?;
    ensure_evaluable(&context)?;
    let reason = NSString::from_str(reason);
    // Wait for the person. A timeout here would abandon a system prompt they may
    // still be answering.
    evaluate(&context, &reason, None)
}

fn new_context() -> Result<objc2::rc::Retained<LAContext>> {
    // SAFETY: LAContext::new has no inputs. The context is retained until
    // evaluation finishes.
    Ok(unsafe { LAContext::new() })
}

fn configure(context: &LAContext, interaction_not_allowed: bool) -> Result<()> {
    // SAFETY: The context is a live LAContext. No credential is supplied, so the
    // framework cannot skip its own password UI. Reuse duration 0 rejects a
    // recent lock-screen unlock.
    unsafe {
        context.setTouchIDAuthenticationAllowableReuseDuration(0.0);
        context.setInteractionNotAllowed(interaction_not_allowed);
        context.setLocalizedFallbackTitle(Some(&*NSString::from_str("Enter Password")));
        for credential_type in [LACredentialType::ApplicationPassword, LACredentialType::SmartCardPIN] {
            context.setCredential_type(None, credential_type);
            if context.isCredentialSet(credential_type) {
                anyhow::bail!("System check refused to start with an injected credential");
            }
        }
    }
    Ok(())
}

fn ensure_evaluable(context: &LAContext) -> Result<()> {
    // SAFETY: canEvaluatePolicy does not prompt. The error is retained by the
    // binding.
    match unsafe { context.canEvaluatePolicy_error(POLICY) } {
        | Ok(()) => Ok(()),
        | Err(error) => Err(error_from_code(error.code())),
    }
}

fn evaluate(context: &LAContext, reason: &NSString, timeout: Option<Duration>) -> Result<()> {
    let (sender, receiver) = mpsc::channel();
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        let code = if error.is_null() {
            None
        } else {
            // SAFETY: LocalAuthentication passes a valid error object for this callback
            // only.
            Some(unsafe { &*error }.code())
        };
        let _ = sender.send(PromptResult {
            success: success.as_bool(),
            code,
        });
    });

    // SAFETY: The reply captures only a Send channel. Context and block stay alive
    // until the callback is received, which is what keeps the evaluation from
    // being cancelled.
    unsafe {
        context.evaluatePolicy_localizedReason_reply(POLICY, reason, &reply);
    }

    let started = Instant::now();
    let run_loop = NSRunLoop::currentRunLoop();
    loop {
        if let Ok(result) = receiver.try_recv() {
            return result.into_result();
        }
        if timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
            // SAFETY: Invalidating a live context cancels the prompt instead of treating
            // the wait as success.
            unsafe { context.invalidate() };
            anyhow::bail!("System authentication timed out before a human completed it");
        }
        let until = NSDate::dateWithTimeIntervalSinceNow(0.05);
        // SAFETY: The default run-loop mode is a process-lifetime framework constant.
        let mode = unsafe { NSDefaultRunLoopMode };
        run_loop.runMode_beforeDate(mode, &until);
    }
}

fn error_from_code(code: NSInteger) -> anyhow::Error {
    let message = match code {
        | code if code == kLAErrorUserCancel as NSInteger => "System authentication was cancelled",
        | code if code == kLAErrorAuthenticationFailed as NSInteger => "System authentication failed",
        | code if code == kLAErrorPasscodeNotSet as NSInteger => {
            "The current user has no password, so system authentication cannot be performed"
        },
        | code if code == kLAErrorNotInteractive as NSInteger => "System authentication requires an interactive prompt",
        | code if code == kLAErrorSystemCancel as NSInteger => "System authentication was cancelled by macOS",
        | code if code == kLAErrorUserFallback as NSInteger => {
            "System authentication did not accept the current user's password prompt"
        },
        | code if code == kLAErrorBiometryLockout as NSInteger => {
            "Touch ID is locked; enter the current user's password in the prompt and try again"
        },
        | code => return anyhow::anyhow!("System authentication failed ({code})"),
    };
    anyhow::anyhow!(message)
}

struct PromptResult {
    success: bool,
    code: Option<NSInteger>,
}

impl PromptResult {
    fn into_result(self) -> Result<()> {
        if self.success {
            return Ok(());
        }
        match self.code {
            | Some(code) => Err(error_from_code(code)),
            | None => anyhow::bail!("System authentication did not succeed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_policy_fails_closed_without_a_human_prompt() -> Result<()> {
        let context = new_context()?;
        configure(&context, true)?;
        let reason = NSString::from_str("unlock profile test");
        let result = evaluate(&context, &reason, Some(Duration::from_secs(2)));

        assert!(
            result.is_err(),
            "system authentication succeeded without a human prompt: {result:?}"
        );
        Ok(())
    }
}
