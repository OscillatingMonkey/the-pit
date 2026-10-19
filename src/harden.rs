//! Process hardening applied at startup.

/// Every process: private file creation, and no core dumps (a core dump of the
/// agent would contain unlocked keys).
pub fn process() {
    unsafe {
        libc::umask(0o077);
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }
}

/// The agent additionally refuses debugger attachment in release builds.
pub fn agent() {
    #[cfg(all(target_os = "macos", not(debug_assertions)))]
    unsafe {
        const PT_DENY_ATTACH: libc::c_int = 31;
        libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Peer credentials of a connected Unix socket: (uid, pid).
#[cfg(target_os = "linux")]
pub fn peer(fd: std::os::fd::RawFd) -> Option<(u32, i32)> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r != 0 {
        return None;
    }
    Some((cred.uid, cred.pid))
}

/// Peer credentials of a connected Unix socket: (uid, pid).
#[cfg(not(target_os = "linux"))]
pub fn peer(fd: std::os::fd::RawFd) -> Option<(u32, i32)> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return None;
    }
    #[cfg(target_os = "macos")]
    let pid = {
        const SOL_LOCAL: libc::c_int = 0;
        const LOCAL_PEERPID: libc::c_int = 2;
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERPID,
                &mut pid as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if r == 0 {
            pid
        } else {
            -1
        }
    };
    #[cfg(not(target_os = "macos"))]
    let pid = -1;
    Some((uid, pid))
}

/// Executable path of a process, for the audit log.
pub fn process_path(pid: i32) -> String {
    #[cfg(target_os = "macos")]
    {
        if pid > 0 {
            let mut buf = vec![0u8; 4096];
            let n = unsafe {
                libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
            };
            if n > 0 {
                return String::from_utf8_lossy(&buf[..n as usize]).into_owned();
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(p) = std::fs::read_link(format!("/proc/{pid}/exe")) {
            return p.display().to_string();
        }
    }
    format!("pid {pid}")
}

/// Parent pid of a process (to name the program that ran `pit`).
pub fn parent_pid(pid: i32) -> i32 {
    #[cfg(target_os = "macos")]
    if let Some(info) = bsd_info(pid) {
        return info.pbi_ppid as i32;
    }
    #[cfg(target_os = "linux")]
    if let Some(f) = proc_stat(pid) {
        return f.first().and_then(|v| v.parse().ok()).unwrap_or(-1);
    }
    let _ = pid;
    -1
}

/// When a process started, so a pid the system has since reused is not taken
/// for the process that had it before.
pub fn start_time(pid: i32) -> Option<u64> {
    #[cfg(target_os = "macos")]
    if let Some(info) = bsd_info(pid) {
        return Some(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec);
    }
    #[cfg(target_os = "linux")]
    if let Some(f) = proc_stat(pid) {
        return f.get(18).and_then(|v| v.parse().ok());
    }
    let _ = pid;
    None
}

#[cfg(target_os = "macos")]
fn bsd_info(pid: i32) -> Option<libc::proc_bsdinfo> {
    if pid <= 0 {
        return None;
    }
    unsafe {
        let mut info: libc::proc_bsdinfo = std::mem::zeroed();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let n = libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        );
        (n == size).then_some(info)
    }
}

/// The fields of `/proc/PID/stat` after the program name, from the parent pid on.
#[cfg(target_os = "linux")]
fn proc_stat(pid: i32) -> Option<Vec<String>> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &s[s.rfind(')')? + 1..];
    Some(rest.split_whitespace().skip(1).map(String::from).collect())
}
