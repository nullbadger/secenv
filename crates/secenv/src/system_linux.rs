//! Current-user authentication on Linux.
//!
//! Callers pass a reason and receive success or failure. A password, when the
//! stack asks for one, is read from the terminal and is not accepted on stdin.
//!
//! libpam is loaded at runtime. Release builds are cross-compiled with zig and
//! cannot run pam-sys's bindgen or link a Linux PAM library.

use {
    anyhow::{
        Context,
        Result,
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
        os::raw::{
            c_char,
            c_int,
            c_void,
        },
        panic::AssertUnwindSafe,
    },
    zeroize::Zeroize,
};

/// The `sudo` service is used because distributions commonly attach both
/// `pam_unix` and `pam_fprintd` there. Fingerprint is offered only when that
/// stack is configured for it.
const SERVICE: &str = "sudo";
const PAM_LIBRARY: &str = "libpam.so.0";

/// Linux-PAM `_pam_types.h`.
const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;
const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x0001;

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
    SystemPam::open()?.authenticate(&username)
}

struct SystemPam {
    library: libloading::Library,
}

impl SystemPam {
    fn open() -> Result<Self> {
        let library = unsafe { libloading::Library::new(PAM_LIBRARY) }
            .with_context(|| format!("System authentication requires {PAM_LIBRARY}"))?;
        Ok(Self { library })
    }

    fn authenticate(&self, username: &str) -> Result<()> {
        let start = self.symbol::<PamStart>(b"pam_start\0")?;
        let authenticate = self.symbol::<PamAuthenticate>(b"pam_authenticate\0")?;
        let acct_mgmt = self.symbol::<PamAcctMgmt>(b"pam_acct_mgmt\0")?;
        let end = self.symbol::<PamEnd>(b"pam_end\0")?;
        let strerror = self.symbol::<PamStrerror>(b"pam_strerror\0")?;

        let service = CString::new(SERVICE).context("PAM service name is not a C string")?;
        let user = CString::new(username).context("Current user name is not a C string")?;
        let conversation = Conversation {
            username: username.to_owned(),
        };
        let conv = PamConv {
            conv: Some(converse),
            appdata_ptr: (&conversation as *const Conversation).cast_mut().cast(),
        };
        let mut handle = std::ptr::null_mut();
        let started = unsafe { start(service.as_ptr(), user.as_ptr(), &conv, &mut handle) };
        if started != PAM_SUCCESS {
            anyhow::bail!("Failed to start system authentication: {}", explain(&strerror, handle, started));
        }

        let authenticated = unsafe { authenticate(handle, PAM_DISALLOW_NULL_AUTHTOK) };
        if authenticated != PAM_SUCCESS {
            let message = explain(&strerror, handle, authenticated);
            unsafe { end(handle, authenticated) };
            anyhow::bail!("System authentication failed: {message}");
        }
        let accounted = unsafe { acct_mgmt(handle, PAM_DISALLOW_NULL_AUTHTOK) };
        let message = explain(&strerror, handle, accounted);
        unsafe { end(handle, accounted) };
        if accounted != PAM_SUCCESS {
            anyhow::bail!("System authentication rejected the current account: {message}");
        }
        Ok(())
    }

    fn symbol<T>(&self, name: &[u8]) -> Result<libloading::Symbol<'_, T>> {
        unsafe { self.library.get(name) }.with_context(|| {
            format!(
                "System authentication library {PAM_LIBRARY} is missing {}",
                String::from_utf8_lossy(name).trim_end_matches('\0')
            )
        })
    }
}

type PamStart = unsafe extern "C" fn(*const c_char, *const c_char, *const PamConv, *mut *mut PamHandle) -> c_int;
type PamAuthenticate = unsafe extern "C" fn(*mut PamHandle, c_int) -> c_int;
type PamAcctMgmt = unsafe extern "C" fn(*mut PamHandle, c_int) -> c_int;
type PamEnd = unsafe extern "C" fn(*mut PamHandle, c_int) -> c_int;
type PamStrerror = unsafe extern "C" fn(*mut PamHandle, c_int) -> *const c_char;

enum PamHandle {}

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: Option<unsafe extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int>,
    appdata_ptr: *mut c_void,
}

struct Conversation {
    username: String,
}

unsafe extern "C" fn converse(
    num_msg: c_int,
    messages: *mut *const PamMessage,
    responses: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| unsafe {
        converse_inner(num_msg, messages, responses, appdata)
    }));
    result.unwrap_or(PAM_CONV_ERR)
}

unsafe fn converse_inner(
    num_msg: c_int,
    messages: *mut *const PamMessage,
    responses: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    if num_msg <= 0 || messages.is_null() || responses.is_null() || appdata.is_null() {
        return PAM_CONV_ERR;
    }
    let conversation = unsafe { &*(appdata as *const Conversation) };
    let count = num_msg as usize;
    let allocated = unsafe { libc::calloc(count, std::mem::size_of::<PamResponse>()) }.cast::<PamResponse>();
    if allocated.is_null() {
        return PAM_BUF_ERR;
    }
    for index in 0..count {
        let message = unsafe { *messages.add(index) };
        if message.is_null() {
            free_responses(allocated, index);
            return PAM_CONV_ERR;
        }
        let message = unsafe { &*message };
        let reply = match message.msg_style {
            | PAM_PROMPT_ECHO_ON => conversation.prompt(message.msg, false),
            | PAM_PROMPT_ECHO_OFF => conversation.prompt(message.msg, true),
            | PAM_ERROR_MSG | PAM_TEXT_INFO => {
                if !message.msg.is_null() {
                    eprintln!("{}", unsafe { CStr::from_ptr(message.msg) }.to_string_lossy());
                }
                Ok(std::ptr::null_mut())
            },
            | _ => Err(PAM_CONV_ERR),
        };
        match reply {
            | Ok(resp) => unsafe {
                (*allocated.add(index)).resp = resp;
                (*allocated.add(index)).resp_retcode = 0;
            },
            | Err(code) => {
                free_responses(allocated, index);
                return code;
            },
        }
    }
    unsafe { *responses = allocated };
    PAM_SUCCESS
}

impl Conversation {
    fn prompt(&self, prompt: *const c_char, hidden: bool) -> Result<*mut c_char, c_int> {
        if prompt.is_null() {
            return Err(PAM_CONV_ERR);
        }
        let prompt = unsafe { CStr::from_ptr(prompt) }.to_string_lossy();
        if !hidden && is_username_prompt(&prompt) {
            return cstring(&self.username);
        }
        let mut value = if hidden {
            rpassword::prompt_password(prompt.as_ref()).map_err(|_| PAM_CONV_ERR)?
        } else {
            eprint!("{prompt}");
            let _ = std::io::stderr().flush();
            let tty = OpenOptions::new()
                .read(true)
                .open("/dev/tty")
                .map_err(|_| PAM_CONV_ERR)?;
            let mut line = String::new();
            BufReader::new(tty)
                .read_line(&mut line)
                .map_err(|_| PAM_CONV_ERR)?;
            line.trim_end_matches(['\n', '\r']).to_string()
        };
        let encoded = cstring(&value);
        value.zeroize();
        encoded
    }
}

fn cstring(value: &str) -> Result<*mut c_char, c_int> {
    CString::new(value).map(|value| value.into_raw()).map_err(|_| PAM_CONV_ERR)
}

fn free_responses(responses: *mut PamResponse, count: usize) {
    if responses.is_null() {
        return;
    }
    for index in 0..count {
        let resp = unsafe { (*responses.add(index)).resp };
        if !resp.is_null() {
            unsafe { drop(CString::from_raw(resp)) };
        }
    }
    unsafe { libc::free(responses.cast()) };
}

fn explain(strerror: &libloading::Symbol<'_, PamStrerror>, handle: *mut PamHandle, status: c_int) -> String {
    let message = unsafe { strerror(handle, status) };
    if message.is_null() {
        return format!("PAM error {status}");
    }
    unsafe { CStr::from_ptr(message) }.to_string_lossy().into_owned()
}

fn is_username_prompt(prompt: &str) -> bool {
    let prompt = prompt.to_ascii_lowercase();
    prompt.contains("login") || prompt.contains("username") || prompt.contains("user name")
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
