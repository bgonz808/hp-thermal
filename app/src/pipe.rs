use std::ptr;

use windows::Win32::Foundation::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::*;
use windows::Win32::System::Pipes::*;
use windows::Win32::System::Threading::*;
use windows::core::{PCWSTR, PWSTR};

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

/// Named-pipe security descriptor (SDDL). DACL: Users = read/write, SYSTEM =
/// full, Admins = full. SACL mandatory label (`ML`) at Medium (`ME`) with
/// no-write-up (`NW`): the kernel denies write access to any below-Medium
/// caller (sandboxed / Low-IL / AppContainer) at the object boundary, so the
/// integrity gate does not depend on impersonating the client. See Mandatory
/// Integrity Control (MS Learn). Build-validated by the test below.
const PIPE_SDDL: &str = "D:(A;;GRGW;;;BU)(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NW;;;ME)";

/// Create the named pipe server with a security descriptor allowing BUILTIN\Users.
pub fn server_create() -> windows::core::Result<HANDLE> {
    // SAFETY: All Win32 calls operate on stack-allocated structs and a wide string
    // that outlives the entire block. The SD is freed via LocalFree before return.
    unsafe {
        // Descriptor + rationale: see PIPE_SDDL. Built to a NUL-terminated wide
        // string at runtime (a one-time small alloc) so the SDDL is a single
        // testable constant, not an inline literal.
        let sddl = wide_null(PIPE_SDDL);
        let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(ptr::null_mut());
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1, // SDDL_REVISION_1
            &mut sd,
            None,
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
            // windows-core 0.62 renamed from_win32() -> from_thread() (captures GetLastError).
            return Err(windows::core::Error::from_thread());
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

        // Both fail closed (#159): a wrong/unreadable client path OR a caller whose
        // integrity level we can't confirm denies the connection.
        path_ok && client_integrity_ok(pipe)
    }
}

/// Integrity Level of the interactive-user tray is Medium; sandboxed / Low-IL /
/// AppContainer processes are below it. The pipe's mandatory-label SACL (see
/// `PIPE_SDDL`) already makes the kernel reject a below-Medium *writer* at the
/// object boundary; this is the defense-in-depth code check. It reads the
/// caller's token WITHOUT impersonation — open the client process for a limited
/// query and read its integrity SID — so the service never runs under a client
/// token (keeps us clear of the token-manipulation surface, MITRE ATT&CK T1134).
/// Returns false when the level cannot be determined (fail-closed, #159): the
/// mandatory-label SACL is the kernel backstop, this code check is the belt.
fn client_integrity_ok(pipe: HANDLE) -> bool {
    // SAFETY: GetNamedPipeClientProcessId writes a u32; OpenProcess yields a
    // checked handle (or we defer); OpenProcessToken yields a token we close;
    // the process handle is closed before the token read. No impersonation.
    unsafe {
        // Fail-closed (#159): any inability to read the caller's integrity level denies the
        // connection, rather than the previous fail-open "defer". The mandatory-label SACL on the
        // pipe is the kernel backstop; this is the belt.
        let mut client_pid: u32 = 0;
        if GetNamedPipeClientProcessId(pipe, &mut client_pid).is_err() {
            return false; // cannot identify caller — deny (fail-closed, #159)
        }
        let Ok(process) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, client_pid) else {
            return false; // cannot open caller — deny (fail-closed, #159)
        };
        let mut token = HANDLE::default();
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token).is_ok();
        let _ = CloseHandle(process);
        if !opened {
            return false; // cannot open caller token — deny (fail-closed, #159)
        }
        let level = token_integrity_rid(token);
        let _ = CloseHandle(token);
        match level {
            Some(rid) => rid >= SECURITY_MANDATORY_MEDIUM_RID,
            None => false, // cannot read caller IL — deny (fail-closed, #159)
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

/// The RID for the High mandatory integrity level (0x3000); System is 0x4000.
const SECURITY_MANDATORY_HIGH_RID: u32 = 0x3000;

/// True if THIS process runs at High or System integrity — the SYSTEM service's expected
/// footing. Fail-CLOSED on read failure (a service that cannot prove its own privilege must
/// not do privileged work) — the opposite of the client check, which defers.
pub(crate) fn own_process_is_privileged() -> bool {
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // SAFETY: open our own process token for query only; closed right after reading the RID.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let rid = token_integrity_rid(token);
        let _ = CloseHandle(token);
        matches!(rid, Some(r) if r >= SECURITY_MANDATORY_HIGH_RID)
    }
}

/// Client pipe I/O timeout (#64). The client handle is opened FILE_FLAG_OVERLAPPED so every
/// client read/write is bounded — a slow or hung service can never pin the caller (the tray's
/// UI thread) inside a blocking pipe read, which was the menu/F12 lockout. Generous vs a
/// healthy round-trip (<100ms) so a working-but-slow call is never spuriously failed, but it
/// caps a hang at ~1s per op instead of forever.
const CLIENT_IO_TIMEOUT_MS: u32 = 1000;

/// Overlapped pipe read/write with a bounded wait (CLIENT side; #64). Returns `Some(bytes)`
/// on success, `None` on error OR timeout. On timeout the pending I/O is cancelled and
/// drained so no kernel I/O is still touching `buf` when we return. The `handle` MUST be
/// opened `FILE_FLAG_OVERLAPPED` (see `client_connect`).
unsafe fn io_with_timeout(
    handle: HANDLE,
    buf: &mut [u8],
    write: bool,
    timeout_ms: u32,
) -> Option<u32> {
    // SAFETY: `buf` is caller-owned and outlives the call; we never return while an I/O is
    // still pending against it — on timeout we CancelIoEx + GetOverlappedResult(bwait=true)
    // to force the kernel to finish with `buf` first. `event` is closed before return.
    let Ok(event) = CreateEventW(None, true, false, None) else {
        return None;
    };
    let mut ov = OVERLAPPED {
        hEvent: event,
        ..Default::default()
    };
    let ov_ptr: *mut OVERLAPPED = &mut ov;
    let started = if write {
        WriteFile(handle, Some(&*buf), None, Some(ov_ptr))
    } else {
        ReadFile(handle, Some(buf), None, Some(ov_ptr))
    };
    let mut transferred = 0u32;
    let result = match started {
        Ok(()) => GetOverlappedResult(handle, ov_ptr, &mut transferred, false)
            .ok()
            .map(|()| transferred),
        Err(e) if e.code() == ERROR_IO_PENDING.to_hresult() => {
            if WaitForSingleObject(event, timeout_ms) == WAIT_OBJECT_0 {
                GetOverlappedResult(handle, ov_ptr, &mut transferred, false)
                    .ok()
                    .map(|()| transferred)
            } else {
                let _ = CancelIoEx(handle, Some(ov_ptr as *const OVERLAPPED));
                let _ = GetOverlappedResult(handle, ov_ptr, &mut transferred, true);
                None
            }
        }
        Err(_) => None,
    };
    let _ = CloseHandle(event);
    result
}

/// Read exactly 2 bytes from the pipe (client side), bounded by `CLIENT_IO_TIMEOUT_MS`.
fn read2(handle: HANDLE) -> Option<[u8; 2]> {
    let mut buf = [0u8; 2];
    // SAFETY: valid overlapped client handle from client_connect; `buf` outlives the call.
    let n = unsafe { io_with_timeout(handle, &mut buf, false, CLIENT_IO_TIMEOUT_MS) }?;
    (n == 2).then_some(buf)
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

/// Write a 4-byte pipe request (client side), bounded by `CLIENT_IO_TIMEOUT_MS`.
fn write_request(handle: HANDLE, cmd: u8, payload: u8) -> bool {
    let mut data = build_request_frame(cmd, payload);
    // SAFETY: valid overlapped client handle from client_connect; `data` outlives the call.
    let n = unsafe { io_with_timeout(handle, &mut data, true, CLIENT_IO_TIMEOUT_MS) };
    n == Some(4)
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
    // SAFETY: `name` is a null-terminated wide string on the stack that outlives the calls.
    unsafe {
        let name = wide_null(app::PIPE_NAME);
        // Event-driven (no sleep-retry poll): WaitNamedPipeW blocks until a server instance is
        // available, covering the brief server disconnect->re-listen gap. Returns quickly if the
        // pipe is absent (service down) — then CreateFileW fails and we return None.
        let _ = WaitNamedPipeW(PCWSTR(name.as_ptr()), CLIENT_IO_TIMEOUT_MS);
        CreateFileW(
            PCWSTR(name.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            // #64: overlapped so the client's read/write can be time-bounded (io_with_timeout)
            // and a slow/hung service never pins the tray's UI thread.
            FILE_FLAG_OVERLAPPED,
            None,
        )
        .ok()
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
    fn wire_envelope_is_frozen() {
        // Cross-version safety rests on this envelope NEVER changing: a 4-byte request with a
        // 2-byte magic prefix (and a 2-byte response, enforced by write2/read2's types). All
        // versioning lives in command codes + BUILD_FINGERPRINT, not frame shape — an old and
        // a new build can only interoperate safely if the envelope never drifts. If this test
        // fails you are breaking cross-version compatibility; add a protocol-version handshake
        // (negotiate/refuse) BEFORE changing the wire.
        assert_eq!(
            build_request_frame(0, 0).len(),
            4,
            "request frame is 4 bytes"
        );
        assert_eq!(PIPE_MAGIC.len(), 2, "magic prefix is 2 bytes");
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

    // The pipe SD is an opaque SDDL literal, so validate it at build time: a
    // typo fails `cargo test` on CI instead of at runtime on a user's machine.
    // Parses via the exact Win32 call server_create() uses, then round-trips
    // (with LABEL info) and asserts the mandatory label is Medium / no-write-up.
    #[test]
    fn pipe_sddl_parses_and_labels_medium_no_write_up() {
        // SAFETY: parse PIPE_SDDL into an SD, serialize it back, and free both
        // heap allocations (the SD and the string) via LocalFree before asserting.
        unsafe {
            let wide = wide_null(PIPE_SDDL);
            let mut sd = PSECURITY_DESCRIPTOR(ptr::null_mut());
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                1,
                &mut sd,
                None,
            )
            .expect("PIPE_SDDL must parse");
            assert!(!sd.0.is_null());

            // 0x1F = OWNER|GROUP|DACL|SACL|LABEL. LABEL is required to emit the
            // mandatory-label ACE back into the string form.
            let mut out = PWSTR(ptr::null_mut());
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                1,
                OBJECT_SECURITY_INFORMATION(0x1F),
                &mut out,
                None,
            )
            .expect("SD must serialize");
            let round = out.to_string().expect("valid UTF-16");
            let _ = LocalFree(Some(HLOCAL(out.0 as *mut _)));
            let _ = LocalFree(Some(HLOCAL(sd.0)));

            assert!(
                round.contains("(ML;;NW;;;ME)"),
                "expected a Medium / no-write-up mandatory label, got: {round}"
            );
        }
    }
}
