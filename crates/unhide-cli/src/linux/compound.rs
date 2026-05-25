//! 复合测试 checkallquick / checkallreverse，对应 unhide-linux-compound.c。

use std::mem;
use std::path::Path;

use unhide_core::{run_pipe_lines, warnln};

use super::{Ctx, PS_PROC, PS_THREAD};

/// reverse 测试用的 ps 命令（也用于在输出里识别并排除我们自己 spawn 的 ps）。
const REVERSE_CMD: &str = "ps --no-header -eL o lwp,cmd";

impl Ctx {
    /// 对应 checkallquick()：把多种探测快速组合后判定一致性。
    pub fn checkallquick(&mut self) {
        self.out.msgln_str(
            0,
            "[*]Searching for Hidden processes through  comparison of results of system calls, proc, dir and ps",
        );
        let verbose = self.verbose > 0;

        let curdir = match std::env::current_dir() {
            Ok(d) => d,
            Err(_) => {
                warnln!(
                    self.out,
                    verbose,
                    "Can't get current directory, test aborted."
                );
                return;
            }
        };

        let mut hidenflag = 0;
        for syspids in 1..=self.maxpid {
            if syspids == self.mypid {
                continue;
            }
            let mut found = 0;
            let mut test_number = 0;

            unhide_core::clear_errno();
            unsafe {
                libc::kill(syspids, 0);
            }
            let found_killbefore = i32::from(unhide_core::last_errno() == 0);

            unsafe {
                unhide_core::clear_errno();
                test_number += 1;
                libc::getpriority(libc::PRIO_PROCESS, syspids as libc::id_t);
                if unhide_core::last_errno() == 0 {
                    found += 1;
                }
                unhide_core::clear_errno();
                test_number += 1;
                libc::getpgid(syspids);
                if unhide_core::last_errno() == 0 {
                    found += 1;
                }
                unhide_core::clear_errno();
                test_number += 1;
                libc::getsid(syspids);
                if unhide_core::last_errno() == 0 {
                    found += 1;
                }
                // 注意：quick 这里用返回值 ret==0（不是 errno）。
                unhide_core::clear_errno();
                test_number += 1;
                let mut mask: libc::cpu_set_t = mem::zeroed();
                let r =
                    libc::sched_getaffinity(syspids, mem::size_of::<libc::cpu_set_t>(), &mut mask);
                if r == 0 {
                    found += 1;
                }
                unhide_core::clear_errno();
                test_number += 1;
                let mut param: libc::sched_param = mem::zeroed();
                libc::sched_getparam(syspids, &mut param);
                if unhide_core::last_errno() == 0 {
                    found += 1;
                }
                unhide_core::clear_errno();
                test_number += 1;
                libc::sched_getscheduler(syspids);
                if unhide_core::last_errno() == 0 {
                    found += 1;
                }
                unhide_core::clear_errno();
                test_number += 1;
                let mut tp: libc::timespec = mem::zeroed();
                libc::sched_rr_get_interval(syspids, &mut tp);
                if unhide_core::last_errno() == 0 {
                    found += 1;
                }
            }

            let directory = format!("/proc/{}", syspids);

            test_number += 1;
            if Path::new(&directory).exists() {
                found += 1;
            }

            test_number += 1;
            if std::env::set_current_dir(&directory).is_ok() {
                found += 1;
                if std::env::set_current_dir(&curdir).is_err() {
                    warnln!(
                        self.out,
                        verbose,
                        "Can't go back to unhide directory, test aborted."
                    );
                    return;
                }
            }

            test_number += 1;
            if std::fs::read_dir(&directory).is_ok() {
                found += 1;
            }

            // 有人看到才调 checkps。
            if found != 0 || found_killbefore != 0 {
                test_number += 1;
                if self.checkps(syspids, PS_PROC | PS_THREAD) {
                    found += 1;
                }
            }

            unhide_core::clear_errno();
            unsafe {
                libc::kill(syspids, 0);
            }
            let found_killafter = i32::from(unhide_core::last_errno() == 0);

            if found_killbefore == found_killafter {
                if !((found_killbefore == 0 && found == 0)
                    || (found_killbefore == 1 && found == test_number))
                {
                    self.printbadpid(syspids);
                    hidenflag = 1;
                }
            } else {
                unhide_core::clear_errno();
                warnln!(
                    self.out,
                    verbose,
                    "syscall comparison test skipped for PID {}.",
                    syspids
                );
            }
        }

        if self.humanfriendly {
            if hidenflag == 0 {
                self.out.msgln_str(0, "No hidden PID found\n");
            } else {
                self.out.msgln_str(0, "");
            }
        }
    }

    /// 对应 checkallreverse()：验证 ps 看到的每个线程内核也看得到，否则是 FAKE 进程。
    pub fn checkallreverse(&mut self) {
        self.out.msgln_str(
            0,
            "[*]Searching for Fake processes by verifying that all threads seen by ps are also seen by others",
        );
        let verbose = self.verbose > 0;

        let lines = match run_pipe_lines(REVERSE_CMD) {
            None => {
                warnln!(
                    self.out,
                    verbose,
                    "Couldn't run command: {}, test aborted",
                    REVERSE_CMD
                );
                return;
            }
            Some(l) => l,
        };

        let curdir = match std::env::current_dir() {
            Ok(d) => d,
            Err(_) => {
                warnln!(
                    self.out,
                    verbose,
                    "Can't get current directory, test aborted"
                );
                return;
            }
        };

        let mut hidenflag = 0;
        let mut last_syspids: i64 = 0;

        for raw in &lines {
            let trimmed = raw.trim_start_matches(' ');
            let lwp: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
            // curline = lwp 之后的部分（含前导空格与命令），并补回原版 getline 携带的换行。
            let curline = format!("{}\n", &trimmed[lwp.len()..]);
            let syspids: i64 = lwp.parse().unwrap_or(0);
            last_syspids = syspids;

            if syspids == 0 {
                unhide_core::clear_errno();
                warnln!(
                    self.out,
                    verbose,
                    "No numeric pid found on ps output line, skip line"
                );
                continue;
            }
            if syspids == self.mypid as i64 {
                continue;
            }

            let pid = syspids as i32;
            let mut not_seen = 0;

            unhide_core::clear_errno();
            unsafe {
                libc::kill(pid, 0);
            }
            let found_killbefore = i32::from(unhide_core::last_errno() == 0);

            let directory = format!("/proc/{}", lwp);

            if !Path::new(&directory).exists() {
                not_seen += 1;
            }
            if std::env::set_current_dir(&directory).is_err() {
                not_seen += 1;
            } else if std::env::set_current_dir(&curdir).is_err() {
                warnln!(
                    self.out,
                    verbose,
                    "Can't go back to unhide directory, test aborted"
                );
                return;
            }
            if std::fs::read_dir(&directory).is_err() {
                not_seen += 1;
            }

            unsafe {
                unhide_core::clear_errno();
                libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t);
                if unhide_core::last_errno() != 0 {
                    not_seen += 1;
                }
                unhide_core::clear_errno();
                libc::getpgid(pid);
                if unhide_core::last_errno() != 0 {
                    not_seen += 1;
                }
                unhide_core::clear_errno();
                libc::getsid(pid);
                if unhide_core::last_errno() != 0 {
                    not_seen += 1;
                }
                unhide_core::clear_errno();
                let mut mask: libc::cpu_set_t = mem::zeroed();
                let r = libc::sched_getaffinity(pid, mem::size_of::<libc::cpu_set_t>(), &mut mask);
                if r != 0 {
                    not_seen += 1;
                }
                unhide_core::clear_errno();
                let mut param: libc::sched_param = mem::zeroed();
                libc::sched_getparam(pid, &mut param);
                if unhide_core::last_errno() != 0 {
                    not_seen += 1;
                }
                unhide_core::clear_errno();
                libc::sched_getscheduler(pid);
                if unhide_core::last_errno() != 0 {
                    not_seen += 1;
                }
                unhide_core::clear_errno();
                let mut tp: libc::timespec = mem::zeroed();
                libc::sched_rr_get_interval(pid, &mut tp);
                if unhide_core::last_errno() != 0 {
                    not_seen += 1;
                }
            }

            unhide_core::clear_errno();
            unsafe {
                libc::kill(pid, 0);
            }
            let found_killafter = i32::from(unhide_core::last_errno() == 0);

            if found_killbefore == found_killafter {
                if found_killafter == 1 {
                    if not_seen != 0 && !curline.contains(REVERSE_CMD) {
                        self.out.msgln_str(
                            0,
                            &format!(
                                "Found FAKE PID: {}\tCommand = {} not seen by {} system function(s)",
                                syspids, curline, not_seen
                            ),
                        );
                        self.found_hp = 1;
                        hidenflag = 1;
                    }
                } else if !curline.contains(REVERSE_CMD) {
                    // 连 kill 都看不到，更可疑：把两次 kill 也算进看不到的接口数。
                    self.out.msgln_str(
                        0,
                        &format!(
                            "Found FAKE PID: {}\tCommand = {} not seen by {} system function(s)",
                            syspids,
                            curline,
                            not_seen + 2
                        ),
                    );
                    self.found_hp = 1;
                    hidenflag = 1;
                }
            } else {
                unhide_core::clear_errno();
                warnln!(
                    self.out,
                    verbose,
                    "reverse test skipped for PID {}",
                    syspids
                );
            }
        }

        // 原版 getline 在 EOF 返回 -1，故 verbose 下结尾总会打印此告警。
        warnln!(
            self.out,
            verbose,
            "Something went wrong with getline reading pipe, reverse test stopped at PID {}\n",
            last_syspids
        );

        if self.humanfriendly {
            if hidenflag == 0 {
                self.out.msgln_str(0, "No FAKE PID found\n");
            } else {
                self.out.msgln_str(0, "");
            }
        }
    }
}
