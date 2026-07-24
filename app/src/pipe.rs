use std::ptr;

use windows::Win32::Foundation::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::*;
use windows::Win32::System::Pipes::*;
use windows::Win32::System::Threading::*;
use windows::core::{PCWSTR, PWSTR, w};

use crate::app;
use crate::protocol::PIPE_MAGIC;
use crate::wide::wide_null;

/// Resolve a process's full image path from its PID via
/// `QueryFullProcessImageNameW`. `None` if the process can't be opened or read.
/// Safe: any `pid` is accepted (a bad one just yields `None`), and the process
/// handle is always closed before return.
fn process_image_path(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess yields a checked handle (or `None` via `?`);
    // QueryFullProcessImageNameW writes at most `buf.len()` wchars and updates
    // `len`; the handle is closed before return regardless of outcome.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 260];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        let _ = CloseHandle(process);
        if ok.is_err() {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Create the named pipe server with a security descriptor allowing BUILTIN\Users.
pub fn server_create() -> windows::core::Result<HANDLE> {
    // SAFETY: All Win32 calls operate on stack-allocated structs and a wide string
    // that outlives the entire block. The SD is freed via LocalFree before return.
    unsafe {
        // SDDL: Users=read/write, SYSTEM=full, Admins=full
        let sddl = w!("D:(A;;GRGW;;;BU)(A;;GA;;;SY)(A;;GA;;;BA)");
        let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(ptr::null_mut());
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, // SDDL_REVISION_1
            &mut sd, None,
        )?;

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };

        let name = wide_null(app::PIPE_NAME);
        // FILE_FLAG_FIRST_PIPE_INSTANCE: if the name already exists (a squatter
        // registered it first), creation FAILS instead of opening a second
        // instance — so the service refuses to run rather than coexisting with an
        // impostor. Pairs with the client's server-identity check below.
        let pipe = CreateNamedPipeW(
            PCWSTR(name.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(
                PIPE_ACCESS_DUPLEX.0 | FILE_FLAG_OVERLAPPED.0 | FILE_FLAG_FIRST_PIPE_INSTANCE.0,
            ),
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,   // max instances
            256, // out buffer
            256, // in buffer
            0,   // default timeout
            Some(&sa),
        );

        LocalFree(Some(HLOCAL(sd.0)));

        if pipe.is_invalid() {
            // Preserve the real error (ERROR_ACCESS_DENIED / ERROR_PIPE_BUSY when
            // the name was squatted) so the service log shows the true cause.
            return Err(windows::core::Error::from_win32());
        }
        Ok(pipe)
    }
}

/// Wait for a client to connect (with stop-event support).
/// Returns true if a client connected, false if stop was signaled.
pub fn server_wait(pipe: HANDLE, stop_event: HANDLE) -> bool {
    // SAFETY: `pipe` and `stop_event` are valid handles from caller; OVERLAPPED
    // lives on the stack for the duration of the wait; event is closed before return.
    unsafe {
        let Ok(connect_event) = CreateEventW(None, true, false, None) else {
            return false;
        };
        let mut overlapped = OVERLAPPED {
            hEvent: connect_event,
            ..Default::default()
        };

        let _ = ConnectNamedPipe(pipe, Some(&mut overlapped));

        let handles = [connect_event, stop_event];
        let wait = WaitForMultipleObjects(&handles, false, INFINITE);

        let _ = CloseHandle(connect_event);

        // WAIT_OBJECT_0 = client connected, WAIT_OBJECT_0+1 = stop signaled
        wait == WAIT_EVENT(0)
    }
}

/// Validate that the connecting client is our own tray executable.
pub fn server_validate_client(pipe: HANDLE) -> bool {
    // SAFETY: `pipe` is a valid named-pipe handle from caller. `buf` is a
    // stack-allocated 260-char array (MAX_PATH); `len` is set to buf capacity.
    // Process handle is closed before return.
    unsafe {
        let mut client_pid: u32 = 0;
        if GetNamedPipeClientProcessId(pipe, &mut client_pid).is_err() {
            return false;
        }

        let Some(client_path) = process_image_path(client_pid) else {
            return false;
        };

        // Client must be our exact exe: same directory AND same filename.
        // Directory check prevents random processes from connecting.
        // Filename check prevents a malicious exe dropped alongside ours.
        let client = std::path::Path::new(&client_path);
        let us = std::path::Path::new(app::exe_path());

        let path_ok = client.parent() == us.parent()
            && client
                .file_name()
                .is_some_and(|f| f.eq_ignore_ascii_case(app::EXE_NAME));

        // Path check fails closed; integrity-level check fails open (rejects only
        // a *confirmed* below-Medium caller, never a benign query failure).
        path_ok && client_integrity_ok(pipe)
    }
}

/// Integrity Level of the interactive-user tray is Medium; sandboxed / Low-IL /
/// AppContainer processes are below it. Reject a *confirmed* below-Medium caller.
/// Uses `ImpersonateNamedPipeClient` to read the client's token directly, which
/// also sidesteps the PID-recycle TOCTOU of the path lookup. Returns true when
/// the level cannot be determined (defer to the other layers — never break a
/// legitimate client over a transient API failure).
fn client_integrity_ok(pipe: HANDLE) -> bool {
    // SAFETY: We impersonate the connected client, open the resulting thread
    // token (OpenAsSelf=true so SYSTEM's context is used for the access check),
    // revert immediately, then read the integrity SID from the token buffer.
    // Every handle is closed and impersonation is always reverted.
    unsafe {
        if ImpersonateNamedPipeClient(pipe).is_err() {
            return true; // cannot determine — defer
        }
        let mut token = HANDLE::default();
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token).is_ok();
        let _ = RevertToSelf();
        if !opened {
            return true;
        }
        let level = token_integrity_rid(token);
        let _ = CloseHandle(token);
        match level {
            Some(rid) => rid >= SECURITY_MANDATORY_MEDIUM_RID,
            None => true, // cannot read — defer
        }
    }
}

/// Windows constant: the RID for the Medium mandatory integrity level (0x2000).
const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;

/// Extract the integrity-level RID from a token's mandatory label.
unsafe fn token_integrity_rid(token: HANDLE) -> Option<u32> {
    let mut size = 0u32;
    // First call sizes the buffer (expected to "fail" with insufficient buffer).
    let _ = GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut size);
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    GetTokenInformation(
        token,
        TokenIntegrityLevel,
        Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
        size,
        &mut size,
    )
    .ok()?;
    let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
    let sid = label.Label.Sid;
    if sid.is_invalid() {
        return None;
    }
    let count_ptr = GetSidSubAuthorityCount(sid);
    if count_ptr.is_null() {
        return None;
    }
    let count = *count_ptr;
    if count == 0 {
        return None;
    }
    let rid_ptr = GetSidSubAuthority(sid, (count - 1) as u32);
    if rid_ptr.is_null() {
        return None;
    }
    Some(*rid_ptr)
}

/// Read exactly 2 bytes from the pipe.
fn read2(handle: HANDLE) -> Option<[u8; 2]> {
    // SAFETY: `handle` is a valid pipe handle; `buf` is a 2-byte stack buffer
    // and `read` count is checked to equal 2 before returning data.
    unsafe {
        let mut buf = [0u8; 2];
        let mut read = 0u32;
        let ok = ReadFile(handle, Some(&mut buf), Some(&mut read), None);
        if ok.is_ok() && read == 2 {
            Some(buf)
        } else {
            None
        }
    }
}

/// Validate the magic prefix of a 4-byte frame and extract [command, payload].
/// Pure (no I/O) so the wire-level magic check can be unit-tested directly.
/// NOTE: the magic is a framing marker, not authentication — it rejects
/// accidental/scanning traffic. Real authorization is the pipe DACL + client
/// validation, never these bytes.
fn parse_request_frame(buf: [u8; 4]) -> Option<[u8; 2]> {
    if buf[0] == PIPE_MAGIC[0] && buf[1] == PIPE_MAGIC[1] {
        Some([buf[2], buf[3]])
    } else {
        None
    }
}

/// Build a 4-byte request frame: magic prefix + command + payload.
/// Shared with `parse_request_frame` so read/write framing can't drift apart.
fn build_request_frame(cmd: u8, payload: u8) -> [u8; 4] {
    [PIPE_MAGIC[0], PIPE_MAGIC[1], cmd, payload]
}

/// Read a 4-byte pipe request, validate the magic prefix, return the 2-byte
/// command+payload. Silently drops connections with wrong magic or short reads.
pub fn read_request(handle: HANDLE) -> Option<[u8; 2]> {
    // SAFETY: `handle` is a valid pipe handle; `buf` is a 4-byte stack buffer.
    unsafe {
        let mut buf = [0u8; 4];
        let mut read = 0u32;
        let ok = ReadFile(handle, Some(&mut buf), Some(&mut read), None);
        if ok.is_ok() && read == 4 {
            parse_request_frame(buf)
        } else {
            None
        }
    }
}

/// Write a 4-byte pipe request: magic prefix + command + payload.
fn write_request(handle: HANDLE, cmd: u8, payload: u8) -> bool {
    let data = build_request_frame(cmd, payload);
    // SAFETY: `handle` is a valid pipe handle; data is a 4-byte stack array.
    unsafe {
        let mut written = 0u32;
        WriteFile(handle, Some(&data), Some(&mut written), None).is_ok() && written == 4
    }
}

/// Write exactly 2 bytes to the pipe (used for server responses).
pub fn write2(handle: HANDLE, data: &[u8; 2]) -> bool {
    // SAFETY: `handle` is a valid pipe handle; `data` is a 2-byte borrowed
    // slice that outlives the WriteFile call.
    unsafe {
        let mut written = 0u32;
        WriteFile(handle, Some(data), Some(&mut written), None).is_ok() && written == 2
    }
}

/// Disconnect the current client so the pipe can accept the next one.
pub fn server_disconnect(pipe: HANDLE) {
    // SAFETY: `pipe` is a valid named-pipe server handle; FlushFileBuffers
    // and DisconnectNamedPipe are safe to call on any valid pipe handle.
    unsafe {
        let _ = FlushFileBuffers(pipe);
        let _ = DisconnectNamedPipe(pipe);
    }
}

/// Connect to the pipe as a client (from the tray app).
/// Retries briefly if the server is between disconnect and re-listen.
pub fn client_connect() -> Option<HANDLE> {
    // SAFETY: `name` is a null-terminated wide string on the stack that outlives
    // each CreateFileW call. Returned handle is valid or the call is retried.
    unsafe {
        let name = wide_null(app::PIPE_NAME);
        for _ in 0..5 {
            let handle = CreateFileW(
                PCWSTR(name.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            );
            if let Ok(h) = handle {
                return Some(h);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        None
    }
}

/// Validate that the pipe server is our own service, not an impostor that
/// squatted the pipe name. Fails CLOSED on a confirmed mismatch (server not our
/// Program Files exe), fails OPEN when the server can't be queried (defer to the
/// pipe DACL + magic rather than break a legitimate connection).
fn client_validate_server(pipe: HANDLE) -> bool {
    // SAFETY: `pipe` is a connected client handle. The server process handle is
    // opened with QUERY_LIMITED_INFORMATION (works across the privilege boundary)
    // and closed before return; `buf` is a MAX_PATH wide buffer.
    unsafe {
        let mut server_pid: u32 = 0;
        if GetNamedPipeServerProcessId(pipe, &mut server_pid).is_err() {
            return true; // cannot determine — defer
        }
        let Some(server_path) = process_image_path(server_pid) else {
            return true; // cannot open/read (policy/AV) — don't break the legit path
        };

        // Confirmed determination: the server must be our exe in our directory.
        // Program Files is admin-only-write, so a user-level squatter can't be here.
        let server = std::path::Path::new(&server_path);
        let us = std::path::Path::new(app::exe_path());
        server.parent() == us.parent()
            && server
                .file_name()
                .is_some_and(|f| f.eq_ignore_ascii_case(app::EXE_NAME))
    }
}

/// Send a 2-byte request and receive a 2-byte response (client side).
pub fn client_transact(cmd: u8, payload: u8) -> Option<[u8; 2]> {
    let handle = client_connect()?;
    // Mutual auth: confirm we're talking to our real service before sending.
    if !client_validate_server(handle) {
        // SAFETY: `handle` is a valid pipe handle from client_connect().
        unsafe {
            let _ = CloseHandle(handle);
        }
        return None;
    }
    let sent = write_request(handle, cmd, payload);
    if !sent {
        // SAFETY: `handle` is a valid pipe handle returned by client_connect().
        unsafe {
            let _ = CloseHandle(handle);
        }
        return None;
    }
    let resp = read2(handle);
    // SAFETY: Same valid pipe handle contract as above.
    unsafe {
        let _ = CloseHandle(handle);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrips_through_build_and_parse() {
        for (cmd, payload) in [(0x01u8, 0u8), (0x02, 3), (0x0A, 100), (0xFF, 0xFF)] {
            let frame = build_request_frame(cmd, payload);
            assert_eq!(
                &frame[0..2],
                &PIPE_MAGIC,
                "frame must carry the magic prefix"
            );
            assert_eq!(
                parse_request_frame(frame),
                Some([cmd, payload]),
                "our own frame must parse back",
            );
        }
    }

    #[test]
    fn parse_accepts_correct_magic_and_extracts_command_payload() {
        let frame = [PIPE_MAGIC[0], PIPE_MAGIC[1], 0x07, 0x2A];
        assert_eq!(parse_request_frame(frame), Some([0x07, 0x2A]));
    }

    #[test]
    fn parse_rejects_wrong_or_partial_magic() {
        // A frame with a valid-looking command but a bad magic prefix must be
        // dropped at the wire, before any command dispatch.
        assert_eq!(parse_request_frame([0x00, 0x00, 0x01, 0x00]), None);
        // Half-right magic is still rejected (both bytes must match).
        assert_eq!(parse_request_frame([PIPE_MAGIC[0], 0x00, 0x01, 0x00]), None);
        assert_eq!(parse_request_frame([0x00, PIPE_MAGIC[1], 0x01, 0x00]), None);
    }
}
