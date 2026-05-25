//! 跨子命令共享的基础设施：输出/日志层、errno 助手、外部命令(管道)执行、get_max_pid。
//!
//! 设计目标是忠实复刻原版 unhide-output.c 的行为（逐字节对齐输出），
//! 同时把原版的 C 全局状态收敛进各子命令自己持有的结构体里。

pub mod output;
pub mod proc;

pub use output::Output;
pub use proc::{get_max_pid, run_pipe_lines, run_pipe_streamed};

/// 读取当前 errno（跨平台），失败返回 0。
pub fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn errno_ptr() -> *mut i32 {
    libc::__errno_location()
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly"
))]
unsafe fn errno_ptr() -> *mut i32 {
    libc::__error()
}

#[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
unsafe fn errno_ptr() -> *mut i32 {
    libc::__errno()
}

#[cfg(any(target_os = "solaris", target_os = "illumos"))]
unsafe fn errno_ptr() -> *mut i32 {
    libc::___errno()
}

/// 将 errno 清零。syscall 系列检测在调用 libc 函数前必须先清零，
/// 之后用 last_errno() 判断内核可见性（忠实复刻原版"看 errno 而非返回值"的语义）。
pub fn clear_errno() {
    unsafe {
        *errno_ptr() = 0;
    }
}

/// 等价 C 的 strerror(errno)。
pub fn strerror(e: i32) -> String {
    unsafe {
        let p = libc::strerror(e);
        if p.is_null() {
            return String::new();
        }
        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// 打印到 stdout 并写日志，末尾追加 `\n`；indent==1 时前置一个制表符。
/// 对应原版 msgln()。
#[macro_export]
macro_rules! msgln {
    ($out:expr, $indent:expr, $($arg:tt)*) => {
        $out.msgln_str($indent, &format!($($arg)*))
    };
}

/// 仅当 verbose 为真时打印警告到 stderr（前缀 "Warning : "，errno!=0 则附 strerror）。
/// 对应原版 warnln()。errno 在格式化之前抓取，以贴合原版"先存 errno 再 vsnprintf"。
#[macro_export]
macro_rules! warnln {
    ($out:expr, $verbose:expr, $($arg:tt)*) => {{
        let __errno = $crate::last_errno();
        $out.warn_str($verbose, __errno, &format!($($arg)*))
    }};
}

/// 打印错误到 stderr（前缀 "Error : "）后 exit(1)。对应原版 die()。
#[macro_export]
macro_rules! die {
    ($out:expr, $($arg:tt)*) => {{
        let __errno = $crate::last_errno();
        $out.die_str(__errno, &format!($($arg)*))
    }};
}
