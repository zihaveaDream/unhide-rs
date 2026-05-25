//! unhide-posix 子命令：通用 Unix 的隐藏进程检测（对应 unhide-posix.c）。
//! 直接用 printf 风格输出（原版无日志功能）。

use std::io::{self, Write};
use std::path::Path;

use unhide_core::{clear_errno, last_errno, run_pipe_lines};

use crate::PosixArgs;

const MAX_PID: i32 = 8388608;

/// 列出全部 PID 的 ps 管道命令，按平台选择（逐字节对齐原版 COMMAND 宏）。
#[cfg(any(target_os = "linux", target_os = "android"))]
const COMMAND: &str = "ps -eLf | awk '{ print $2 }' | grep -v PID";
#[cfg(target_os = "openbsd")]
const COMMAND: &str = "ps -axk | awk '{ print $1 }' | grep -v PID";
#[cfg(any(target_os = "solaris", target_os = "illumos"))]
const COMMAND: &str = "ps -elf | awk '{ print $4 }' | grep -v PID";
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
const COMMAND: &str = "ps -axH | awk '{ print $1 }' | grep -v PID";
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "openbsd",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "freebsd",
    target_os = "dragonfly"
)))]
const COMMAND: &str = "ps -ax | awk '{ print $1 }' | grep -v PID";

fn header() -> String {
    let mut s = String::new();
    s.push_str("Unhide-posix 20240509\n");
    s.push_str("Copyright © 2013-2024 Yago Jesus & Patrick Gouin\n");
    // 原版同样在 "GPLv3+" 与 ":" 间用 U+00A0。
    s.push_str("License GPLv3+\u{a0}: GNU GPL version 3 or later\n");
    s.push_str("http://www.unhide-forensics.info\n\n");
    s.push_str("NOTE : This is legacy version of unhide, it is intended\n");
    s.push_str("       for systems using Linux < 2.6 or other UNIX systems\n\n");
    s
}

fn prog_name() -> String {
    std::env::args()
        .next()
        .unwrap_or_else(|| "unhide".to_string())
}

/// 对应 checkps()：ps 看不到该 pid 则报隐藏。
fn checkps(tmppid: i32) {
    let compare = tmppid.to_string();
    let mut ok = false;
    if let Some(lines) = run_pipe_lines(COMMAND) {
        for l in &lines {
            if *l == compare {
                ok = true;
                break;
            }
        }
    }
    if !ok {
        print!("Found HIDDEN PID: {}\n", tmppid);
        let cmd = format!("/proc/{}/cmdline", tmppid);
        if Path::new(&cmd).exists() {
            if let Ok(bytes) = std::fs::read(&cmd) {
                let token = bytes.split(|&b| b == 0).next().unwrap_or(&[]);
                print!("Command: {}\n\n", String::from_utf8_lossy(token));
            }
        }
        let _ = io::stdout().flush();
    }
}

fn checkproc() {
    print!("[*]Searching for Hidden processes through /proc scanning\n\n");
    let _ = io::stdout().flush();
    for procpids in 1..=MAX_PID {
        let directory = format!("/proc/{}", procpids);
        if Path::new(&directory).exists() {
            checkps(procpids);
        }
    }
}

fn checkgetpriority() {
    print!("[*]Searching for Hidden processes through getpriority() scanning\n\n");
    let _ = io::stdout().flush();
    for syspids in 1..=MAX_PID {
        clear_errno();
        unsafe {
            libc::getpriority(libc::PRIO_PROCESS, syspids as libc::id_t);
        }
        if last_errno() == 0 {
            checkps(syspids);
        }
    }
}

fn checkgetpgid() {
    print!("[*]Searching for Hidden processes through getpgid() scanning\n\n");
    let _ = io::stdout().flush();
    for syspids in 1..=MAX_PID {
        clear_errno();
        unsafe {
            libc::getpgid(syspids);
        }
        if last_errno() == 0 {
            checkps(syspids);
        }
    }
}

fn checkgetsid() {
    print!("[*]Searching for Hidden processes through getsid() scanning\n\n");
    let _ = io::stdout().flush();
    for syspids in 1..=MAX_PID {
        clear_errno();
        unsafe {
            libc::getsid(syspids);
        }
        if last_errno() == 0 {
            checkps(syspids);
        }
    }
}

pub fn run(a: PosixArgs) -> i32 {
    print!("{}", header());
    let _ = io::stdout().flush();

    if a.args.len() != 1 {
        print!("usage: {} proc | sys\n\n", prog_name());
        let _ = io::stdout().flush();
        return 1;
    }
    match a.args[0].as_str() {
        "proc" => checkproc(),
        "sys" => {
            checkgetpriority();
            checkgetpgid();
            checkgetsid();
        }
        _ => {
            print!("usage: {} proc | sys\n\n", prog_name());
            let _ = io::stdout().flush();
            return 1;
        }
    }
    0
}
