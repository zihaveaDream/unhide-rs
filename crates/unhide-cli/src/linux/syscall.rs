//! 系统调用扫描测试，对应 unhide-linux-syscall.c。
//!
//! 注：原版 checksysinfo4() 存在但未注册进 tab_test，没有任何测试名能触发它，
//! 故此处不实现（保持与 CLI 可达性一致）。

use std::io::{self, Write};
use std::mem;

use unhide_core::{clear_errno, last_errno, run_pipe_streamed, warnln};

use super::{Ctx, PS_PROC, PS_THREAD};

/// SYS_COMMAND 字面量（warnln 用，不含 stdbuf 前缀）。
const SYS_COMMAND: &str = "ps --no-header -eL o lwp";

/// sysinfo().procs。
fn sysinfo_procs() -> i32 {
    unsafe {
        let mut info: libc::sysinfo = mem::zeroed();
        libc::sysinfo(&mut info);
        info.procs as i32
    }
}

impl Ctx {
    /// 8 个单系统调用测试的统一模板：用 errno 判断内核可见性，两次探测夹 checkps。
    fn syscall_scan(&mut self, start: &str, probe: impl Fn(i32)) {
        self.out.msgln_str(0, start);
        for syspids in 1..=self.maxpid {
            clear_errno();
            if syspids == self.mypid {
                continue;
            }
            probe(syspids);
            if last_errno() != 0 {
                continue;
            }
            if self.checkps(syspids, PS_PROC | PS_THREAD) {
                continue;
            }
            clear_errno();
            probe(syspids);
            if last_errno() != 0 {
                continue;
            }
            self.printbadpid(syspids);
        }
    }

    pub fn checkgetpriority(&mut self) {
        self.syscall_scan(
            "[*]Searching for Hidden processes through getpriority() scanning\n",
            |pid| unsafe {
                let _ = libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t);
            },
        );
    }

    pub fn checkgetpgid(&mut self) {
        self.syscall_scan(
            "[*]Searching for Hidden processes through getpgid() scanning\n",
            |pid| unsafe {
                let _ = libc::getpgid(pid);
            },
        );
    }

    pub fn checkgetsid(&mut self) {
        self.syscall_scan(
            "[*]Searching for Hidden processes through getsid() scanning\n",
            |pid| unsafe {
                let _ = libc::getsid(pid);
            },
        );
    }

    pub fn checksched_getaffinity(&mut self) {
        self.syscall_scan(
            "[*]Searching for Hidden processes through sched_getaffinity() scanning\n",
            |pid| unsafe {
                let mut mask: libc::cpu_set_t = mem::zeroed();
                let _ = libc::sched_getaffinity(pid, mem::size_of::<libc::cpu_set_t>(), &mut mask);
            },
        );
    }

    pub fn checksched_getparam(&mut self) {
        self.syscall_scan(
            "[*]Searching for Hidden processes through sched_getparam() scanning\n",
            |pid| unsafe {
                let mut param: libc::sched_param = mem::zeroed();
                let _ = libc::sched_getparam(pid, &mut param);
            },
        );
    }

    pub fn checksched_getscheduler(&mut self) {
        self.syscall_scan(
            "[*]Searching for Hidden processes through sched_getscheduler() scanning\n",
            |pid| unsafe {
                let _ = libc::sched_getscheduler(pid);
            },
        );
    }

    pub fn checksched_rr_get_interval(&mut self) {
        self.syscall_scan(
            "[*]Searching for Hidden processes through sched_rr_get_interval() scanning\n",
            |pid| unsafe {
                let mut tp: libc::timespec = mem::zeroed();
                let _ = libc::sched_rr_get_interval(pid, &mut tp);
            },
        );
    }

    pub fn checkkill(&mut self) {
        self.syscall_scan(
            "[*]Searching for Hidden processes through kill(..,0) scanning\n",
            |pid| unsafe {
                let _ = libc::kill(pid, 0);
            },
        );
    }

    /// 对应 checkallnoprocps()：仅比较各系统调用之间的一致性，不调 ps 也不看 /proc。
    pub fn checkallnoprocps(&mut self) {
        self.out.msgln_str(
            0,
            "[*]Searching for Hidden processes through  comparison of results of system calls\n",
        );
        let verbose = self.verbose > 0;
        for syspids in 1..=self.maxpid {
            if syspids == self.mypid {
                continue;
            }
            let mut found = 0;
            let mut found_killbefore = 0;
            let mut found_killafter = 0;

            clear_errno();
            unsafe {
                let _ = libc::kill(syspids, 0);
            }
            if last_errno() == 0 {
                found_killbefore = 1;
            }

            unsafe {
                clear_errno();
                let _ = libc::getpriority(libc::PRIO_PROCESS, syspids as libc::id_t);
                if last_errno() == 0 {
                    found += 1;
                }
                clear_errno();
                let _ = libc::getpgid(syspids);
                if last_errno() == 0 {
                    found += 1;
                }
                clear_errno();
                let _ = libc::getsid(syspids);
                if last_errno() == 0 {
                    found += 1;
                }
                clear_errno();
                let mut mask: libc::cpu_set_t = mem::zeroed();
                let _ =
                    libc::sched_getaffinity(syspids, mem::size_of::<libc::cpu_set_t>(), &mut mask);
                if last_errno() == 0 {
                    found += 1;
                }
                clear_errno();
                let mut param: libc::sched_param = mem::zeroed();
                let _ = libc::sched_getparam(syspids, &mut param);
                if last_errno() == 0 {
                    found += 1;
                }
                clear_errno();
                let _ = libc::sched_getscheduler(syspids);
                if last_errno() == 0 {
                    found += 1;
                }
                clear_errno();
                let mut tp: libc::timespec = mem::zeroed();
                let _ = libc::sched_rr_get_interval(syspids, &mut tp);
                if last_errno() == 0 {
                    found += 1;
                }
                clear_errno();
                let _ = libc::kill(syspids, 0);
            }
            if last_errno() == 0 {
                found_killafter = 1;
            }

            if found_killbefore == found_killafter {
                if !((found_killbefore == 0 && found == 0) || (found_killbefore == 1 && found == 7))
                {
                    self.printbadpid(syspids);
                }
            } else {
                clear_errno();
                warnln!(
                    self.out,
                    verbose,
                    "syscall comparison test skipped for PID {}.",
                    syspids
                );
            }
        }
    }

    /// genpscmd()：据 -u 决定是否加 stdbuf 前缀，并打印 "Commande : <cmd>"。
    fn genpscmd(&self) -> String {
        let cmd = if self.unbuffered_stdout {
            format!("stdbuf -i0 -o0 -e0 {}", SYS_COMMAND)
        } else {
            SYS_COMMAND.to_string()
        };
        print!("Commande : {}\n", cmd);
        let _ = io::stdout().flush();
        cmd
    }

    /// checksysinfo()（1st variant）。
    pub fn checksysinfo(&mut self) {
        let initial_result = sysinfo_procs();
        let command = self.genpscmd();
        self.out.msgln_str(
            0,
            "[*]Searching for Hidden processes through sysinfo() scanning (1st variant)\n",
        );
        // 流式逐行读取：原版以 stdbuf 强制 ps 逐行输出，并在读每行时重新采样
        // sysinfo()，须用 run_pipe_streamed 才能复刻该 verbose 逐行对比语义。
        // 闭包内收集 (procnumber, result_after_lines, 待打印消息列表)，
        // 闭包结束后再统一写 self.out，避免借用冲突。
        let verbose = self.verbose;
        let mut result = initial_result;
        let mut procnumber = 0i32;
        // (indent, message) 待打印队列
        let mut pending: Vec<(i32, String)> = Vec::new();
        let streamed = run_pipe_streamed(&command, |buf| {
            procnumber += 1;
            if verbose > 0 {
                let now = sysinfo_procs();
                if result != now {
                    pending.push((
                        1,
                        format!(
                            "\tWARNING : info.procs changed during test : {} (was {})",
                            now, result
                        ),
                    ));
                    result = now;
                }
                if verbose >= 2 {
                    pending.push((1, format!("\"{}\"", buf)));
                }
            }
        });
        // 统一输出闭包期间积累的消息
        for (indent, msg) in pending {
            self.out.msgln_str(indent, &msg);
        }
        if streamed.is_none() {
            warnln!(
                self.out,
                self.verbose > 0,
                "Couldn't run command: {}, test aborted",
                SYS_COMMAND
            );
            return;
        }
        let final_result = sysinfo_procs();
        if self.verbose >= 1 && result != final_result {
            self.out.msgln_str(
                1,
                &format!(
                    "\tWARNING : info.procs changed during test : {} (was {})",
                    final_result, result
                ),
            );
        }
        if initial_result == final_result {
            let hidennumber = final_result + 1 - procnumber;
            if hidennumber != 0 {
                self.out.msgln_str(
                    1,
                    &format!(
                        "{} HIDDEN Processes Found\tsysinfo.procs reports {} processes and ps sees {} processes",
                        hidennumber.abs(),
                        final_result,
                        procnumber - 1
                    ),
                );
                self.found_hp = 1;
            }
        } else {
            clear_errno();
            warnln!(
                self.out,
                self.verbose > 0,
                "sysinfo test skipped due to intermittent activity"
            );
        }
    }

    /// checksysinfo2()（2nd variant）。
    pub fn checksysinfo2(&mut self) {
        let command = self.genpscmd();
        self.out.msgln_str(
            0,
            "[*]Searching for Hidden processes through sysinfo() scanning (2nd variant)\n",
        );
        let initial_result = sysinfo_procs();
        // 流式逐行读取，复刻原版 stdbuf 逐行采样 sysinfo() 的语义。
        let verbose = self.verbose;
        let mut result = initial_result;
        let mut procnumber = 0i32;
        let mut pending: Vec<(i32, String)> = Vec::new();
        let streamed = run_pipe_streamed(&command, |buf| {
            procnumber += 1;
            if verbose > 0 {
                let now = sysinfo_procs();
                if result != now {
                    pending.push((
                        1,
                        format!(
                            "\tWARNING : info.procs changed during test : {} (was {})",
                            now, result
                        ),
                    ));
                    result = now;
                }
                if verbose >= 2 {
                    pending.push((1, format!("\"{}\"", buf)));
                }
            }
        });
        for (indent, msg) in pending {
            self.out.msgln_str(indent, &msg);
        }
        if streamed.is_none() {
            warnln!(
                self.out,
                self.verbose > 0,
                "Couldn't run command: {}, test aborted",
                SYS_COMMAND
            );
            return;
        }
        let final_result = sysinfo_procs();
        if self.verbose >= 1 && result != final_result {
            self.out.msgln_str(
                1,
                &format!(
                    "\tWARNING : info.procs changed during test : {} (was {})",
                    final_result, result
                ),
            );
        }
        if initial_result == final_result {
            let hidennumber = final_result - procnumber;
            if hidennumber != 0 {
                self.out.msgln_str(
                    1,
                    &format!(
                        "{} HIDDEN Processes Found\tsysinfo.procs reports {} processes and ps sees {} processes",
                        hidennumber.abs(),
                        final_result,
                        procnumber
                    ),
                );
                self.found_hp = 1;
            }
        } else {
            clear_errno();
            warnln!(
                self.out,
                self.verbose > 0,
                "sysinfo test skipped due to intermittent activity"
            );
        }
    }

    /// checksysinfo3()（3rd variant，极简版）。
    pub fn checksysinfo3(&mut self) {
        let command = self.genpscmd();
        self.out.msgln_str(
            0,
            "[*]Searching for Hidden processes through sysinfo() scanning (3rd variant)\n",
        );
        let initial_result = sysinfo_procs();
        // 流式逐行计数（3rd variant 无 verbose 采样，仅需总行数）。
        let mut procnumber = 0i32;
        let streamed = run_pipe_streamed(&command, |_buf| {
            procnumber += 1;
        });
        if streamed.is_none() {
            warnln!(
                self.out,
                self.verbose > 0,
                "Couldn't run command: {}, test aborted",
                SYS_COMMAND
            );
            return;
        }
        let final_result = sysinfo_procs();
        if initial_result == final_result {
            let hidennumber = final_result - procnumber;
            if hidennumber != 0 {
                self.out.msgln_str(
                    1,
                    &format!(
                        "{} HIDDEN Processes Found\tsysinfo.procs reports {} processes and ps sees {} processes",
                        hidennumber.abs(),
                        final_result,
                        procnumber
                    ),
                );
                self.found_hp = 1;
            }
        } else {
            clear_errno();
            warnln!(
                self.out,
                self.verbose > 0,
                "sysinfo test skipped due to intermittent activity"
            );
        }
    }
}
