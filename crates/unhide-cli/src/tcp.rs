//! unhide-tcp 子命令：检测被隐藏的 TCP/UDP 端口。
//! 对应 unhide-tcp.c + unhide-tcp-fast.c。

use std::io::{self, Write};
use std::mem;

use unhide_core::{die, run_pipe_lines, warnln, Output};

use crate::TcpArgs;

/// tcp header（注意：与 linux/posix 不同，原版此处用普通空格，无 NBSP；只有 4 行）。
const HEADER: &str = concat!(
    "Unhide-tcp 20240509\n",
    "Copyright © 2010-2024 Yago Jesus & Patrick Gouin\n",
    "License GPLv3+ : GNU GPL version 3 or later\n",
    "http://www.unhide-forensics.info\n",
);

#[derive(Clone, Copy, PartialEq)]
enum Proto {
    Tcp,
    Udp,
}

// ss 命令（带 %d 端口占位）。
const TCP_CMD_SS: &str =
    r"ss -tan sport = :%d | sed -e '/[\.:][0-9]/!d' -e 's/.*[\.:]\([0-9]*\) .*[\.:].*/\1/'";
const UDP_CMD_SS: &str =
    r"ss -uan sport = :%d | sed -e '/[\.:][0-9]/!d' -e 's/.*[\.:]\([0-9]*\) .*[\.:].*/\1/'";

// netstat 整表命令（按平台）。
#[cfg(any(target_os = "openbsd", target_os = "freebsd", target_os = "dragonfly"))]
const TCP_CMD_NETSTAT: &str =
    r"netstat -an -p tcp | sed -e '/[\.:][0-9]/!d' -e 's/.*[\.:]\([0-9]*\) .*[\.:].*/\1/'";
#[cfg(any(target_os = "openbsd", target_os = "freebsd", target_os = "dragonfly"))]
const UDP_CMD_NETSTAT: &str =
    r"netstat -an -p udp| sed -e '/[\.:][0-9]/!d' -e 's/.*[\.:]\([0-9]*\) .*[\.:].*/\1/'";

#[cfg(any(target_os = "solaris", target_os = "illumos"))]
const TCP_CMD_NETSTAT: &str =
    r"netstat -an -P tcp | sed -e '/[\.:][0-9]/!d' -e 's/.*[\.:]\([0-9]*\) .*[\.:].*/\1/'";
#[cfg(any(target_os = "solaris", target_os = "illumos"))]
const UDP_CMD_NETSTAT: &str =
    r"netstat -an -P udp| sed -e '/[\.:][0-9]/!d' -e 's/.*[\.:]\([0-9]*\) .*[\.:].*/\1/'";

#[cfg(not(any(
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos"
)))]
const TCP_CMD_NETSTAT: &str =
    r"netstat -tan | sed -e '/[\.:][0-9]/!d' -e 's/.*[\.:]\([0-9]*\) .*[\.:].*/\1/'";
#[cfg(not(any(
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos"
)))]
const UDP_CMD_NETSTAT: &str =
    r"netstat -uan | sed -e '/[\.:][0-9]/!d' -e 's/.*[\.:]\([0-9]*\) .*[\.:].*/\1/'";

// fuser / sockstat。
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
const FUSER_TCP: &str = "sockstat -46 -p %d -P tcp";
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
const FUSER_UDP: &str = "sockstat -46 -p %d -P udp";
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
const FUSER_NAME: &str = "sockstat";

#[cfg(not(any(target_os = "freebsd", target_os = "dragonfly")))]
const FUSER_TCP: &str = "fuser -v -n tcp %d 2>&1";
#[cfg(not(any(target_os = "freebsd", target_os = "dragonfly")))]
const FUSER_UDP: &str = "fuser -v -n udp %d 2>&1";
#[cfg(not(any(target_os = "freebsd", target_os = "dragonfly")))]
const FUSER_NAME: &str = "fuser";

const LSOF_TCP: &str = "lsof +c 0 -iTCP:%d";
const LSOF_UDP: &str = "lsof +c 0 -iUDP:%d";

#[cfg(any(target_os = "linux", target_os = "android"))]
const DEFAULT_USE_SS: bool = true;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const DEFAULT_USE_SS: bool = false;

struct TcpCtx {
    out: Output,
    verbose: i32,
    use_fuser: bool,
    use_lsof: bool,
    use_ss: bool,
    use_quick: bool,
    humanfriendly: bool,
    logtofile: bool,
    checker: String,
    hidden_found: i32,
}

fn make_addr(port: u16) -> libc::sockaddr_in {
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr.s_addr = libc::INADDR_ANY;
    addr.sin_port = port.to_be();
    addr
}

unsafe fn do_bind(fd: i32, addr: &libc::sockaddr_in) -> i32 {
    libc::bind(
        fd,
        addr as *const libc::sockaddr_in as *const libc::sockaddr,
        mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    )
}

fn prog_name() -> String {
    std::env::args()
        .next()
        .unwrap_or_else(|| "unhide".to_string())
}

fn eaddrinuse() -> bool {
    unhide_core::last_errno() == libc::EADDRINUSE
}

impl TcpCtx {
    /// 对应 print_info()：跑 fuser/lsof/sockstat 并展示其输出。
    fn print_info(&mut self, prog_name: &str, command_fmt: &str, port: i32) {
        let command = command_fmt.replace("%d", &port.to_string());
        match run_pipe_lines(&command) {
            None => {
                warnln!(
                    self.out,
                    self.verbose > 0,
                    "Couldn't run command: {}",
                    command
                );
            }
            Some(lines) => {
                self.out.msgln_str(1, &format!("{} reports :", prog_name));
                // 原版 msgln(1, buffer) 的 buffer 含结尾换行 → 每行输出为 "\t<内容>\n\n"。
                for line in &lines {
                    self.out.msgln_str(1, &format!("{}\n", line));
                }
            }
        }
    }

    /// 对应 print_port()。
    fn print_port(&mut self, proto: Proto, port: i32) {
        self.out.msgln_str(
            0,
            &format!(
                "\nFound Hidden port that not appears in {}: {}",
                self.checker, port
            ),
        );
        if self.use_fuser {
            let (fmt, name) = match proto {
                Proto::Tcp => (FUSER_TCP, FUSER_NAME),
                Proto::Udp => (FUSER_UDP, FUSER_NAME),
            };
            self.print_info(name, fmt, port);
        }
        if self.use_lsof {
            let fmt = match proto {
                Proto::Tcp => LSOF_TCP,
                Proto::Udp => LSOF_UDP,
            };
            self.print_info("lsof", fmt, port);
        }
    }

    /// 对应 checkoneport()：ss/netstat 是否看得到该端口。返回 true=看得到。
    fn checkoneport(&mut self, port: i32, command: &str) -> bool {
        let compare = port.to_string();
        match run_pipe_lines(command) {
            Some(lines) => {
                for line in &lines {
                    // 去掉尾部所有非数字字符后比较。
                    let trimmed = line.trim_end_matches(|c: char| !c.is_ascii_digit());
                    if trimmed == compare {
                        return true;
                    }
                }
                false
            }
            None => {
                die!(
                    self.out,
                    "Couldn't execute command : {} while checking port {}",
                    command,
                    port
                );
            }
        }
    }

    /// 暴力逐个检查 TCP 端口（默认方法）。
    fn print_hidden_tcp_1by1(&mut self) {
        self.hidden_found = 0;
        for i in 1..=65535u32 {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd == -1 {
                warnln!(
                    self.out,
                    self.verbose > 0,
                    "can't create socket while checking port {}/tcp",
                    i
                );
                continue;
            }
            let addr = make_addr(i as u16);
            unhide_core::clear_errno();
            let bind_ret = unsafe { do_bind(fd, &addr) };
            if bind_ret != -1 {
                unsafe { libc::listen(fd, 1) };
                if eaddrinuse() {
                    let cmd = if self.use_ss {
                        TCP_CMD_SS.replace("%d", &i.to_string())
                    } else {
                        TCP_CMD_NETSTAT.to_string()
                    };
                    if !self.checkoneport(i as i32, &cmd) {
                        unsafe { libc::listen(fd, 1) };
                        if eaddrinuse() {
                            self.hidden_found += 1;
                            self.print_port(Proto::Tcp, i as i32);
                        }
                    }
                }
            } else if eaddrinuse() {
                let cmd = if self.use_ss {
                    TCP_CMD_SS.replace("%d", &i.to_string())
                } else {
                    TCP_CMD_NETSTAT.to_string()
                };
                if !self.checkoneport(i as i32, &cmd) {
                    let bind_ret2 = unsafe { do_bind(fd, &addr) };
                    if bind_ret2 == -1 {
                        if eaddrinuse() {
                            self.hidden_found += 1;
                            self.print_port(Proto::Tcp, i as i32);
                        } else {
                            warnln!(
                                self.out,
                                self.verbose > 0,
                                "can't bind to socket while checking port {}",
                                i
                            );
                        }
                    }
                }
            }
            unsafe { libc::close(fd) };
        }
    }

    /// 暴力逐个检查 UDP 端口（默认方法）。
    fn print_hidden_udp_1by1(&mut self) {
        self.hidden_found = 0;
        for u in 1..=65535u32 {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if fd == -1 {
                warnln!(
                    self.out,
                    self.verbose > 0,
                    "can't create socket while checking port {}/udp",
                    u
                );
                continue;
            }
            let addr = make_addr(u as u16);
            unhide_core::clear_errno();
            let bind_ret = unsafe { do_bind(fd, &addr) };
            if bind_ret != 0 {
                if eaddrinuse() {
                    let cmd = if self.use_ss {
                        UDP_CMD_SS.replace("%d", &u.to_string())
                    } else {
                        UDP_CMD_NETSTAT.to_string()
                    };
                    if !self.checkoneport(u as i32, &cmd) {
                        let bind_ret2 = unsafe { do_bind(fd, &addr) };
                        if bind_ret2 != 0 && eaddrinuse() {
                            self.hidden_found += 1;
                            self.print_port(Proto::Udp, u as i32);
                        }
                    }
                } else {
                    warnln!(
                        self.out,
                        self.verbose > 0,
                        "can't bind to socket while checking port {}",
                        u
                    );
                }
            }
            unsafe { libc::close(fd) };
        }
    }

    // ---- server 快速法（fast.c）----

    fn get_netstat_ports(&mut self, proto: Proto, netstat_ports: &mut [u8; 65536]) {
        let cmd = match proto {
            Proto::Tcp => TCP_CMD_NETSTAT,
            Proto::Udp => UDP_CMD_NETSTAT,
        };
        let lines = match run_pipe_lines(cmd) {
            Some(l) => l,
            None => {
                die!(
                    self.out,
                    "popen failed to open netstat to get the ports list"
                );
            }
        };
        for p in netstat_ports.iter_mut() {
            *p = 0;
        }
        for line in &lines {
            if let Ok(port) = line.trim().parse::<usize>() {
                if port < 65536 {
                    netstat_ports[port] = 1;
                }
            }
        }
    }

    fn check(
        &mut self,
        proto: Proto,
        check_ports: &mut [u8; 65536],
        hidden_ports: &mut [u8; 65536],
    ) {
        let protocol = match proto {
            Proto::Tcp => libc::SOCK_STREAM,
            Proto::Udp => libc::SOCK_DGRAM,
        };
        for p in hidden_ports.iter_mut() {
            *p = 0;
        }
        self.hidden_found = 0;

        let mut netstat_ports = [0u8; 65536];
        self.get_netstat_ports(proto, &mut netstat_ports);

        for i in 0..65536usize {
            if check_ports[i] == 0 || netstat_ports[i] != 0 {
                continue;
            }
            let fd = unsafe { libc::socket(libc::AF_INET, protocol, 0) };
            if fd == -1 {
                die!(self.out, "socket creation failed");
            }
            let reuseaddr: libc::c_int = 1;
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &reuseaddr as *const libc::c_int as *const libc::c_void,
                    mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                unsafe { libc::close(fd) };
                die!(self.out, "setsockopt can't set SO_REUSEADDR");
            }
            let addr = make_addr(i as u16);
            unhide_core::clear_errno();
            let bind_bad = unsafe { do_bind(fd, &addr) } != 0;
            let listen_bad = proto == Proto::Tcp && unsafe { libc::listen(fd, 1) } != 0;
            if bind_bad || listen_bad {
                if eaddrinuse() {
                    hidden_ports[i] = 1;
                    self.hidden_found += 1;
                } else {
                    warnln!(
                        self.out,
                        self.verbose > 0,
                        "bind failed, maybe you are not root?"
                    );
                    check_ports[i] = 0;
                }
            } else {
                check_ports[i] = 0;
            }
            unsafe { libc::close(fd) };
        }
    }

    fn print_hidden_ports(&mut self, proto: Proto) {
        let mut check_ports = [1u8; 65536];
        let mut hidden_ports = [0u8; 65536];

        self.check(proto, &mut check_ports, &mut hidden_ports);
        if self.hidden_found != 0 {
            check_ports.copy_from_slice(&hidden_ports);
            self.check(proto, &mut check_ports, &mut hidden_ports);
        }
        if self.hidden_found != 0 {
            for i in 0..65536usize {
                if hidden_ports[i] != 0 {
                    self.print_port(proto, i as i32);
                }
            }
        }
    }
}

fn usage(command: &str) {
    let mut s = String::new();
    s.push_str(&format!("Usage: {} [options] \n\n", command));
    s.push_str("Options :\n");
    s.push_str("   -V          Show version and exit\n");
    s.push_str("   -v          verbose\n");
    s.push_str("   -h          display this help\n");
    s.push_str("   -f          show fuser output for hidden ports\n");
    s.push_str("   -l          show lsof output for hidden ports\n");
    s.push_str("   -o          log result into unhide-tcp.log file\n");
    s.push_str("   -s          use very quick version for server with lot of opened ports\n");
    s.push_str("   -n          use netstat instead of ss\n");
    print!("{}", s);
    let _ = io::stdout().flush();
}

pub fn run(args: TcpArgs) -> i32 {
    print!("{}", HEADER);
    let _ = io::stdout().flush();

    let prog = prog_name();

    if unsafe { libc::getuid() } != 0 {
        let mut out = Output::new();
        unhide_core::clear_errno();
        die!(out, "You must be root to run {} !", prog);
    }

    if args.help {
        usage(&prog);
        return 0;
    }
    if args.version {
        return 0;
    }

    let mut verbose = args.v as i32;
    if args.verbose_long && verbose == 0 {
        verbose = 1;
    }
    if args.brief {
        verbose = 0;
    }
    let use_ss = DEFAULT_USE_SS && !args.netstat;

    let mut ctx = TcpCtx {
        out: Output::new(),
        verbose,
        use_fuser: args.fuser,
        use_lsof: args.lsof,
        use_ss,
        use_quick: args.server,
        humanfriendly: args.bigh,
        logtofile: args.log,
        checker: if use_ss {
            "ss".to_string()
        } else {
            "netstat".to_string()
        },
        hidden_found: 0,
    };

    // used_options 串。
    let mut used = String::from("Used options: ");
    if ctx.verbose > 0 {
        used.push_str("verbose ");
    }
    if ctx.use_lsof {
        used.push_str("use_lsof ");
    }
    if ctx.use_fuser {
        used.push_str("use_fuser ");
    }
    if !ctx.use_ss {
        used.push_str("use_netstat ");
    }
    if ctx.use_quick {
        used.push_str("use_quick ");
    }
    if ctx.logtofile {
        used.push_str("logtofile ");
    }

    if ctx.logtofile {
        ctx.out.open_log("unhide-tcp", HEADER, ctx.humanfriendly);
    }
    ctx.out.msgln_str(0, &used);

    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, -20);
    }

    let mut ret_code = 0;

    ctx.out.msgln_str(0, "[*]Starting TCP checking");
    if ctx.use_quick {
        ctx.print_hidden_ports(Proto::Tcp);
    } else {
        ctx.print_hidden_tcp_1by1();
    }
    if ctx.hidden_found != 0 {
        ret_code += 4;
    }

    ctx.out.msgln_str(0, "[*]Starting UDP checking");
    if ctx.use_quick {
        ctx.print_hidden_ports(Proto::Udp);
    } else {
        ctx.print_hidden_udp_1by1();
    }
    if ctx.hidden_found != 0 {
        ret_code += 8;
    }

    if ctx.logtofile {
        ctx.out.close_log("unhide-tcp", ctx.humanfriendly);
    }
    ret_code
}
