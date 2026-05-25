//! `unhide` —— 单一二进制 + 子命令，忠实复刻原版 unhide-linux / unhide-posix /
//! unhide-tcp / unhide_rb 四个工具。
//!
//! 子命令：
//!   unhide linux [options] <test_list...>   (仅 Linux)
//!   unhide posix <proc|sys>                 (通用 Unix)
//!   unhide tcp   [options]                  (Linux/macOS/*BSD)
//!   unhide rb                               (仅 Linux)

use clap::{ArgAction, Args, Parser, Subcommand};

mod tcp;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod rb;

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos"
))]
mod posix;

#[derive(Parser)]
#[command(
    name = "unhide",
    version,
    about = "Forensic tool to find hidden processes and TCP/UDP ports (Rust port of UnHide)",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Detect hidden processes on Linux >= 2.6 (original: unhide-linux)
    Linux(LinuxArgs),
    /// Detect hidden processes on generic Unix systems (original: unhide-posix)
    Posix(PosixArgs),
    /// Detect hidden TCP/UDP ports (original: unhide-tcp)
    Tcp(TcpArgs),
    /// C/Rust port of the ruby unhide.rb (toy / proof of fake, Linux only)
    Rb,
}

/// unhide-linux 的选项。禁用 clap 自带 help/version，改为手动处理，
/// 以忠实复刻原版"先打印 header、再 root 检查、最后处理 -h/-V"的顺序。
#[derive(Args)]
#[command(disable_help_flag = true, disable_version_flag = true)]
pub struct LinuxArgs {
    /// do a double check in brute test
    #[arg(short = 'd')]
    pub d: bool,
    /// log result into a log file
    #[arg(short = 'f')]
    pub f: bool,
    /// same as -f
    #[arg(short = 'o')]
    pub o: bool,
    /// display help
    #[arg(short = 'h', long = "help")]
    pub help: bool,
    /// more checks
    #[arg(short = 'm', long = "morecheck")]
    pub m: bool,
    /// use alternate sysinfo test in meta-test
    #[arg(short = 'r', long = "alt-sysinfo")]
    pub r: bool,
    /// show version and exit
    #[arg(short = 'V', long = "version")]
    pub version: bool,
    /// be verbose (repeatable)
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub v: u8,
    /// inhibit stdout buffering of subprocesses
    #[arg(short = 'u')]
    pub u: bool,
    /// slightly human friendlier output
    #[arg(short = 'H', long = "human-frienly")]
    pub bigh: bool,
    /// same as -d
    #[arg(long = "brute-doublecheck")]
    pub brute_doublecheck: bool,
    /// same as -f
    #[arg(long = "log")]
    pub log: bool,
    /// list of tests to run
    #[arg(value_name = "TEST")]
    pub test_list: Vec<String>,
}

/// unhide-posix 的参数：恰好一个 `proc` 或 `sys`。
#[derive(Args)]
pub struct PosixArgs {
    #[arg(value_name = "proc|sys")]
    pub args: Vec<String>,
}

/// unhide-tcp 的选项。同样禁用 clap 自带 help/version 以忠实复刻顺序。
#[derive(Args)]
#[command(disable_help_flag = true, disable_version_flag = true)]
pub struct TcpArgs {
    /// show fuser output for hidden ports
    #[arg(short = 'f', long = "fuser")]
    pub fuser: bool,
    /// display help
    #[arg(short = 'h', long = "help")]
    pub help: bool,
    /// show lsof output for hidden ports
    #[arg(short = 'l', long = "lsof")]
    pub lsof: bool,
    /// log result into a log file
    #[arg(short = 'o', long = "log")]
    pub log: bool,
    /// use very quick version for servers with many opened ports
    #[arg(short = 's', long = "server")]
    pub server: bool,
    /// use netstat instead of ss
    #[arg(short = 'n', long = "netstat")]
    pub netstat: bool,
    /// be verbose (repeatable)
    #[arg(short = 'v', action = ArgAction::Count)]
    pub v: u8,
    /// verbose (long form, sets verbose on)
    #[arg(long = "verbose")]
    pub verbose_long: bool,
    /// don't display warning messages (default)
    #[arg(long = "brief")]
    pub brief: bool,
    /// show version and exit
    #[arg(short = 'V')]
    pub version: bool,
    /// slightly human friendlier output (hidden)
    #[arg(short = 'H', hide = true)]
    pub bigh: bool,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Cmd::Linux(a) => run_linux(a),
        Cmd::Posix(a) => run_posix(a),
        Cmd::Tcp(a) => tcp::run(a),
        Cmd::Rb => run_rb(),
    };
    std::process::exit(code);
}

#[cfg(target_os = "linux")]
fn run_linux(a: LinuxArgs) -> i32 {
    linux::run(a)
}
#[cfg(not(target_os = "linux"))]
fn run_linux(_a: LinuxArgs) -> i32 {
    eprintln!(
        "unhide linux: not available on this platform (Linux >= 2.6 only). Try 'unhide posix'."
    );
    1
}

#[cfg(target_os = "linux")]
fn run_rb() -> i32 {
    rb::run()
}
#[cfg(not(target_os = "linux"))]
fn run_rb() -> i32 {
    eprintln!("unhide rb: not available on this platform (Linux >= 2.6 only).");
    1
}

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos"
))]
fn run_posix(a: PosixArgs) -> i32 {
    posix::run(a)
}
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos"
)))]
fn run_posix(_a: PosixArgs) -> i32 {
    eprintln!("unhide posix: not available on this platform.");
    1
}
