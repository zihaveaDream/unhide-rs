//! unhide-linux 子命令：检测被隐藏的进程（仅 Linux >= 2.6）。
//! 忠实复刻 unhide-linux.c / unhide-linux-{procfs,syscall,bruteforce,compound}.c。

use std::io::{self, Write};
use std::path::Path;

use unhide_core::{die, run_pipe_lines, warnln, Output};

use crate::LinuxArgs;

mod bruteforce;
mod compound;
mod procfs;
mod syscall;

/// 启动横幅（逐字节对齐原版 header[]，含 UTF-8 `©` 与末尾空格）。
pub const HEADER: &str = concat!(
    "Unhide 20240509\n",
    "Copyright © 2010-2024 Yago Jesus & Patrick Gouin\n",
    // 注意：原版此处 "GPLv3+" 与 ":" 之间是 U+00A0 不间断空格（逐字节对齐）。
    "License GPLv3+\u{a0}: GNU GPL version 3 or later\n",
    "http://www.unhide-forensics.info\n\n",
    "NOTE : This version of unhide is for systems using Linux >= 2.6 \n\n",
);

// checkps 的检查掩码。
pub const PS_PROC: u32 = 0x0000_0001;
pub const PS_THREAD: u32 = 0x0000_0002;
pub const PS_MORE: u32 = 0x0000_0004;

const DEFAULT_MAX_PID: i32 = 8388608;

/// 运行期共享状态（替代原版的 C 全局变量）。
pub struct Ctx {
    pub out: Output,
    pub maxpid: i32,
    pub mypid: i32,
    pub verbose: i32,
    pub morecheck: bool,
    pub rt_sys: bool,
    pub brute_simple_check: bool,
    pub unbuffered_stdout: bool,
    pub humanfriendly: bool,
    pub found_hp: i32,
}

impl Ctx {
    fn new() -> Self {
        Ctx {
            out: Output::new(),
            maxpid: DEFAULT_MAX_PID,
            mypid: 0,
            verbose: 0,
            morecheck: false,
            rt_sys: false,
            brute_simple_check: true,
            unbuffered_stdout: false,
            humanfriendly: false,
            found_hp: 0,
        }
    }

    /// 对应 checkps()：返回 true 表示 ps 看得到该 pid（正常），false 表示看不到（疑似隐藏）。
    pub fn checkps(&mut self, tmppid: i32, checks: u32) -> bool {
        let compare = tmppid.to_string();

        if checks & PS_PROC != 0 {
            let command = format!("ps --no-header -p {} o pid", tmppid);
            match run_pipe_lines(&command) {
                None => {
                    warnln!(
                        self.out,
                        self.verbose > 0,
                        "Couldn't run command: {} while ps checking pid {}",
                        command,
                        tmppid
                    );
                    return false;
                }
                Some(lines) => {
                    // 原版只读一行。
                    if let Some(first) = lines.first() {
                        if first.trim_start_matches(' ') == compare {
                            return true;
                        }
                    }
                }
            }
        }

        if checks & PS_THREAD != 0 {
            let command = "ps --no-header -eL o lwp";
            match run_pipe_lines(command) {
                None => {
                    warnln!(
                        self.out,
                        self.verbose > 0,
                        "Couldn't run command: {} while ps checking pid {}",
                        command,
                        tmppid
                    );
                    return false;
                }
                Some(lines) => {
                    for l in &lines {
                        if l.trim_start_matches(' ') == compare {
                            return true;
                        }
                    }
                }
            }
        }

        if checks & PS_MORE != 0 {
            let command = format!("ps --no-header -s {} o sess", tmppid);
            match run_pipe_lines(&command) {
                None => {
                    warnln!(
                        self.out,
                        self.verbose > 0,
                        "Couldn't run command: {} while ps checking pid {}",
                        command,
                        tmppid
                    );
                    return false;
                }
                Some(lines) => {
                    for l in &lines {
                        if l.trim_start_matches(' ') == compare {
                            return true;
                        }
                    }
                }
            }
            let command2 = "ps --no-header -eL o pgid";
            match run_pipe_lines(command2) {
                None => {
                    warnln!(
                        self.out,
                        self.verbose > 0,
                        "Couldn't run command: {} while ps checking pid {}",
                        command2,
                        tmppid
                    );
                    return false;
                }
                Some(lines) => {
                    for l in &lines {
                        if l.trim_start_matches(' ') == compare {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// 对应 printbadpid()：打印一个被隐藏 pid 的详细信息（逐字节对齐原版）。
    pub fn printbadpid(&mut self, tmppid: i32) {
        self.found_hp = 1;
        let verbose = self.verbose > 0;
        self.out
            .msgln_str(0, &format!("Found HIDDEN PID: {}", tmppid));

        // ---- cmdline ----
        let cmdline_path = format!("/proc/{}/cmdline", tmppid);
        let mut cmdok = 0;
        if Path::new(&cmdline_path).exists() {
            match std::fs::read(&cmdline_path) {
                Ok(bytes) => {
                    let first = bytes.split(|&b| b == 0).next().unwrap_or(&[]);
                    if !first.is_empty() {
                        let s = String::from_utf8_lossy(first);
                        self.out.msgln_str(0, &format!("\tCmdline: \"{}\"", s));
                        cmdok += 1;
                    }
                    // 原版 getline 在读完后再次命中 EOF 返回 -1，故 verbose 下会打印此告警。
                    warnln!(
                        self.out,
                        verbose,
                        "Something went wrong with getline reading pipe"
                    );
                }
                Err(_) => {}
            }
        }
        if cmdok == 0 {
            self.out.msgln_str(0, "\tCmdline: \"<none>\"");
        }

        // ---- exe link ----
        let exe_path = format!("/proc/{}/exe", tmppid);
        match std::fs::read_link(&exe_path) {
            Ok(target) => {
                self.out.msgln_str(
                    0,
                    &format!("\tExecutable: \"{}\"", target.to_string_lossy()),
                );
                cmdok += 1;
            }
            Err(e) => {
                // 原版：lstat 失败 → "<no link>"；lstat 成功但 readlink 失败 → "<nonexistant>"。
                use std::io::ErrorKind;
                if e.kind() == ErrorKind::NotFound {
                    self.out.msgln_str(0, "\tExecutable: \"<no link>\"");
                } else {
                    self.out.msgln_str(0, "\tExecutable: \"<nonexistant>\"");
                }
            }
        }

        // ---- comm（内部命令名）----
        let comm_path = format!("/proc/{}/comm", tmppid);
        if Path::new(&comm_path).exists() {
            match std::fs::read_to_string(&comm_path) {
                Ok(content) => {
                    let name = content.strip_suffix('\n').unwrap_or(&content);
                    if cmdok == 0 {
                        // 既无 cmdline 又无 exe → 内核线程，加方括号。
                        self.out.msgln_str(0, &format!("\tCommand: \"[{}]\"", name));
                    } else {
                        self.out.msgln_str(0, &format!("\tCommand: \"{}\"", name));
                    }
                }
                Err(_) => {
                    self.out.msgln_str(0, "\tCommand: \"can't read file\"");
                }
            }
        } else {
            self.out
                .msgln_str(0, "\t\"<No comm file>\"  ... maybe a transitory process\"");
        }

        // ---- environ: USER / PWD ----
        let environ_path = format!("/proc/{}/environ", tmppid);
        if Path::new(&environ_path).exists() {
            let usercmd = format!(
                "cat /proc/{}/environ | tr \"\\0\" \"\\n\" | grep -w 'USER'",
                tmppid
            );
            match run_pipe_lines(&usercmd) {
                None => {
                    warnln!(self.out, verbose, "\tCouldn't read USER for pid {}", tmppid)
                }
                Some(lines) => match lines.first() {
                    Some(first) => self.out.msgln_str(0, &format!("\t${}", first)),
                    None => self.out.msgln_str(0, "\t$USER=<undefined>"),
                },
            }
            let pwdcmd = format!(
                "cat /proc/{}/environ | tr \"\\0\" \"\\n\" | grep -w 'PWD'",
                tmppid
            );
            match run_pipe_lines(&pwdcmd) {
                None => warnln!(self.out, verbose, "\tCouldn't read PWD for pid {}", tmppid),
                Some(lines) => match lines.first() {
                    Some(first) => self.out.msgln_str(0, &format!("\t${}", first)),
                    None => self.out.msgln_str(0, "\t$PWD=<undefined>"),
                },
            }
        }

        // 原版结尾的额外空行（仅 stdout）。
        print!("\n");
        let _ = io::stdout().flush();
    }
}

/// 待执行测试集合（对应 tab_test 的 todo 标志，按枚举顺序执行）。
#[derive(Default)]
struct Todo {
    proc_: bool,
    chdir: bool,
    opendir: bool,
    readdir: bool,
    getprio: bool,
    getpgid: bool,
    getsid: bool,
    getaff: bool,
    getparm: bool,
    getsched: bool,
    rrint: bool,
    kill: bool,
    noprocps: bool,
    brute: bool,
    reverse: bool,
    quickonly: bool,
    sysinfo: bool,
    sysinfo2: bool,
    sysinfo3: bool,
}

/// 把一个测试名映射到 todo（标准测试展开为基础测试组合）。未知名返回 false。
fn add_test(name: &str, t: &mut Todo) -> bool {
    match name {
        "proc" | "checkproc" => t.proc_ = true,
        "procfs" => {
            t.chdir = true;
            t.opendir = true;
            t.readdir = true;
        }
        "procall" => {
            t.proc_ = true;
            t.chdir = true;
            t.opendir = true;
            t.readdir = true;
        }
        "sys" => {
            // 注意：原版已把 sysinfo 从 sys 中移除（易误报）。
            t.kill = true;
            t.noprocps = true;
            t.getprio = true;
            t.getpgid = true;
            t.getsid = true;
            t.getaff = true;
            t.getparm = true;
            t.getsched = true;
            t.rrint = true;
        }
        "quick" | "checkquick" => t.quickonly = true,
        "brute" | "checkbrute" => t.brute = true,
        "reverse" | "checkreverse" => t.reverse = true,
        "opendir" | "checkopendir" => t.opendir = true,
        "checksysinfo" => t.sysinfo = true,
        "checksysinfo2" => t.sysinfo2 = true,
        "checksysinfo3" => t.sysinfo3 = true,
        "checkchdir" => t.chdir = true,
        "checkreaddir" => t.readdir = true,
        "checkkill" => t.kill = true,
        "checknoprocps" => t.noprocps = true,
        "checkgetprio" => t.getprio = true,
        "checkgetpgid" => t.getpgid = true,
        "checkgetsid" => t.getsid = true,
        "checkgetaffinity" => t.getaff = true,
        "checkgetparam" => t.getparm = true,
        "checkgetsched" => t.getsched = true,
        "checkRRgetinterval" => t.rrint = true,
        _ => return false,
    }
    true
}

/// 对应 usage()（逐行逐字节对齐原版）。
fn usage(command: &str) {
    let mut s = String::new();
    s.push_str(&format!("Usage: {} [options] test_list\n\n", command));
    s.push_str("Option :\n");
    s.push_str("   -V          Show version and exit\n");
    s.push_str("   -v          verbose\n");
    s.push_str("   -h          display this help\n");
    s.push_str("   -m          more checks (available only with procfs, checkopendir & checkchdir commands)\n");
    s.push_str("   -r          use alternate sysinfo test in meta-test\n");
    s.push_str("   -f          log result into unhide-linux.log file\n");
    s.push_str("   -o          same as '-f'\n");
    s.push_str("   -d          do a double check in brute test\n");
    s.push_str(
        "   -u          inhibit stdout buffering of subprocesses (needs stdbuf command)\n\n",
    );
    s.push_str("Test_list :\n");
    s.push_str("   Test_list is one or more of the following\n");
    s.push_str("   Standard tests :\n");
    s.push_str("      brute\n");
    s.push_str("      proc\n");
    s.push_str("      procall\n");
    s.push_str("      procfs\n");
    s.push_str("      quick\n");
    s.push_str("      reverse\n");
    s.push_str("      sys\n");
    s.push_str("   Elementary tests :\n");
    s.push_str("      checkbrute\n");
    s.push_str("      checkchdir\n");
    s.push_str("      checkgetaffinity\n");
    s.push_str("      checkgetparam\n");
    s.push_str("      checkgetpgid\n");
    s.push_str("      checkgetprio\n");
    s.push_str("      checkRRgetinterval\n");
    s.push_str("      checkgetsched\n");
    s.push_str("      checkgetsid\n");
    s.push_str("      checkkill\n");
    s.push_str("      checknoprocps\n");
    s.push_str("      checkopendir\n");
    s.push_str("      checkproc\n");
    s.push_str("      checkquick\n");
    s.push_str("      checkreaddir\n");
    s.push_str("      checkreverse\n");
    s.push_str("      checksysinfo\n");
    s.push_str("      checksysinfo2\n");
    s.push_str("      checksysinfo3\n");
    print!("{}", s);
    let _ = io::stdout().flush();
}

fn prog_name() -> String {
    std::env::args()
        .next()
        .unwrap_or_else(|| "unhide".to_string())
}

/// 对应 C 的 atoi()：取开头的十进制整数。
pub(crate) fn atoi(s: &str) -> i32 {
    let digits: String = s
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().unwrap_or(0)
}

pub fn run(args: LinuxArgs) -> i32 {
    print!("{}", HEADER);
    let _ = io::stdout().flush();

    let prog = prog_name();

    // root 检查（先清 errno，避免附带无关的 strerror）。
    if unsafe { libc::getuid() } != 0 {
        let mut out = Output::new();
        unhide_core::clear_errno();
        die!(out, "You must be root to run {} !", prog);
    }

    let mut ctx = Ctx::new();
    ctx.maxpid = unhide_core::get_max_pid(&mut ctx.out, DEFAULT_MAX_PID);

    // 对应原版 argc<2（无任何参数）→ usage + exit(1)。
    let no_args = args.test_list.is_empty()
        && !args.d
        && !args.f
        && !args.o
        && !args.help
        && !args.m
        && !args.r
        && args.v == 0
        && !args.u
        && !args.bigh
        && !args.brute_doublecheck
        && !args.log
        && !args.version;
    if no_args {
        usage(&prog);
        return 1;
    }
    if args.help {
        usage(&prog);
        return 0;
    }
    if args.version {
        return 0; // header 已打印
    }

    // 选项映射。
    ctx.verbose = args.v as i32;
    ctx.morecheck = args.m;
    if ctx.morecheck && ctx.verbose == 0 {
        ctx.verbose = 1; // -m implies -v
    }
    ctx.rt_sys = args.r;
    ctx.brute_simple_check = !(args.d || args.brute_doublecheck);
    ctx.unbuffered_stdout = args.u;
    ctx.humanfriendly = args.bigh;
    let logtofile = args.f || args.o || args.log;

    // 解析测试列表。
    let mut todo = Todo::default();
    for name in &args.test_list {
        if !add_test(name, &mut todo) {
            print!("Unknown argument: {}\n", name);
            usage(&prog);
            return 0;
        }
    }

    // used_options 串。
    let mut used = String::from("Used options: ");
    if ctx.verbose > 0 {
        used.push_str("verbose ");
    }
    if !ctx.brute_simple_check {
        used.push_str("brutesimplecheck ");
    }
    if ctx.morecheck {
        used.push_str("morecheck ");
    }
    if ctx.rt_sys {
        used.push_str("RTsys ");
    }
    if logtofile {
        used.push_str("logtofile ");
    }
    if ctx.unbuffered_stdout {
        used.push_str("unbufferedstdout ");
    }

    if logtofile {
        ctx.out.open_log("unhide-linux", HEADER, ctx.humanfriendly);
    }
    ctx.out.msgln_str(0, &used);

    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, -20);
    }
    ctx.mypid = unsafe { libc::getpid() };

    // 按枚举顺序执行被选中的测试。
    if todo.proc_ {
        ctx.checkproc();
    }
    if todo.chdir {
        ctx.checkchdir();
    }
    if todo.opendir {
        ctx.checkopendir();
    }
    if todo.readdir {
        ctx.checkreaddir();
    }
    if todo.getprio {
        ctx.checkgetpriority();
    }
    if todo.getpgid {
        ctx.checkgetpgid();
    }
    if todo.getsid {
        ctx.checkgetsid();
    }
    if todo.getaff {
        ctx.checksched_getaffinity();
    }
    if todo.getparm {
        ctx.checksched_getparam();
    }
    if todo.getsched {
        ctx.checksched_getscheduler();
    }
    if todo.rrint {
        ctx.checksched_rr_get_interval();
    }
    if todo.kill {
        ctx.checkkill();
    }
    if todo.noprocps {
        ctx.checkallnoprocps();
    }
    if todo.brute {
        ctx.brute();
    }
    if todo.reverse {
        ctx.checkallreverse();
    }
    if todo.quickonly {
        ctx.checkallquick();
    }
    if todo.sysinfo {
        ctx.checksysinfo();
    }
    if todo.sysinfo2 {
        ctx.checksysinfo2();
    }
    if todo.sysinfo3 {
        ctx.checksysinfo3();
    }

    if logtofile {
        ctx.out.close_log("unhide-linux", ctx.humanfriendly);
    }
    if ctx.humanfriendly {
        print!("Done !\n\n");
        let _ = io::stdout().flush();
    }
    let _ = io::stdout().flush();
    ctx.found_hp
}
