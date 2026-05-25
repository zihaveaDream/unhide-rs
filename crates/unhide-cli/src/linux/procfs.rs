//! procfs 扫描测试：checkproc / checkchdir / checkopendir / checkreaddir。
//! 对应 unhide-linux-procfs.c。

use std::path::Path;

use unhide_core::warnln;

use super::{atoi, Ctx, PS_PROC, PS_THREAD};

/// 从 status 文件内容里取 Tgid 数字串（去前导空格/tab，取连续数字）。
fn parse_tgid(content: &str) -> Option<String> {
    for line in content.lines() {
        if line.starts_with("Tgid:") {
            let rest = line[5..].trim_start_matches([' ', '\t']);
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            return Some(digits);
        }
    }
    None
}

impl Ctx {
    /// 对应 checkproc()：用 stat() 探测 /proc/<pid> 是否存在。
    pub fn checkproc(&mut self) {
        self.out.msgln_str(
            0,
            "[*]Searching for Hidden processes through /proc stat scanning\n",
        );

        for procpids in 1..=self.maxpid {
            if procpids == self.mypid {
                continue;
            }
            let directory = format!("/proc/{}", procpids);
            if !Path::new(&directory).exists() {
                continue;
            }
            if self.checkps(procpids, PS_PROC | PS_THREAD) {
                continue;
            }
            // 再探一次以排除瞬时进程。
            if !Path::new(&directory).exists() {
                continue;
            }
            self.printbadpid(procpids);
        }
    }

    /// 对应 checkchdir()：用 chdir() 探测 /proc/<pid>。
    pub fn checkchdir(&mut self) {
        self.out.msgln_str(
            0,
            "[*]Searching for Hidden processes through /proc chdir scanning\n",
        );

        let verbose = self.verbose > 0;
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

        for procpids in 1..=self.maxpid {
            if procpids == self.mypid {
                continue;
            }
            let directory = format!("/proc/{}", procpids);
            if std::env::set_current_dir(&directory).is_err() {
                continue;
            }

            if self.morecheck {
                let status_path = format!("{}/status", directory);
                match std::fs::read_to_string(&status_path) {
                    Err(_) => {
                        warnln!(
                            self.out,
                            verbose,
                            "can't open status file for process: {}",
                            procpids
                        );
                        continue;
                    }
                    Ok(content) => match parse_tgid(&content) {
                        Some(tgid) => {
                            let tgid10 = &tgid[..tgid.len().min(10)];
                            let new_directory = format!("/proc/{}/task/{}", tgid10, procpids);
                            if std::env::set_current_dir(&new_directory).is_err() {
                                unhide_core::clear_errno();
                                warnln!(
                                    self.out,
                                    true,
                                    "Thread {} said it's in group {} but isn't listed in {}",
                                    procpids,
                                    tgid,
                                    new_directory
                                );
                            }
                        }
                        None => {
                            unhide_core::clear_errno();
                            warnln!(
                                self.out,
                                true,
                                "Can't find TGID in status file for process: {}",
                                procpids
                            );
                        }
                    },
                }
            }

            // 解锁该 proc 目录，让瞬时进程可消失。
            if std::env::set_current_dir(&curdir).is_err() {
                warnln!(
                    self.out,
                    verbose,
                    "Can't go back to unhide directory, test aborted"
                );
                return;
            }

            if self.checkps(procpids, PS_PROC | PS_THREAD) {
                continue;
            }

            // 排除短命进程的假阳性。
            if std::env::set_current_dir(&directory).is_err() {
                continue;
            }
            self.printbadpid(procpids);
        }

        if std::env::set_current_dir(&curdir).is_err() {
            warnln!(
                self.out,
                verbose,
                "Can't go back to unhide directory, test aborted"
            );
        }
    }

    /// 对应 checkopendir()：用 opendir() 探测 /proc/<pid>。
    pub fn checkopendir(&mut self) {
        self.out.msgln_str(
            0,
            "[*]Searching for Hidden processes through /proc opendir scanning\n",
        );

        for procpids in 1..=self.maxpid {
            if procpids == self.mypid {
                continue;
            }
            let directory = format!("/proc/{}", procpids);
            // opendir 探测并立即关闭。
            if std::fs::read_dir(&directory).is_err() {
                continue;
            }

            if self.morecheck {
                let status_path = format!("{}/status", directory);
                match std::fs::read_to_string(&status_path) {
                    Err(_) => {
                        // 注意：checkopendir 此处用 msgln（不是 warnln）。
                        self.out.msgln_str(
                            0,
                            &format!("Can't open status file for process: {}", procpids),
                        );
                        continue;
                    }
                    Ok(content) => match parse_tgid(&content) {
                        Some(tgid) => {
                            let tgid10 = &tgid[..tgid.len().min(10)];
                            let new_directory = format!("/proc/{}/task/{}", tgid10, procpids);
                            if std::fs::read_dir(&new_directory).is_err() {
                                unhide_core::clear_errno();
                                warnln!(
                                    self.out,
                                    true,
                                    "Thread {} said it's in group {} but isn't listed in {}",
                                    procpids,
                                    tgid,
                                    new_directory
                                );
                            }
                        }
                        None => {
                            unhide_core::clear_errno();
                            warnln!(
                                self.out,
                                true,
                                "Can't find TGID in status file for process: {}",
                                procpids
                            );
                        }
                    },
                }
            }

            if self.checkps(procpids, PS_PROC | PS_THREAD) {
                continue;
            }

            // 排除短命进程的假阳性。
            if std::fs::read_dir(&directory).is_err() {
                continue;
            }
            self.printbadpid(procpids);
        }
    }

    /// 对应 checkreaddir()：遍历 /proc 各进程的 task 目录找隐藏线程。
    pub fn checkreaddir(&mut self) {
        self.out.msgln_str(
            0,
            "[*]Searching for Hidden thread through /proc/pid/task readdir scanning\n",
        );

        let verbose = self.verbose > 0;
        let procdir = match std::fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => {
                warnln!(
                    self.out,
                    verbose,
                    "Cannot open /proc directory ! Exiting test."
                );
                return;
            }
        };

        for entry in procdir.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                continue;
            }
            let name10 = &name[..name.len().min(10)];
            let task = format!("/proc/{}/task", name10);
            let taskdir = match std::fs::read_dir(&task) {
                Ok(d) => d,
                Err(_) => {
                    warnln!(
                        self.out,
                        verbose,
                        "Cannot open {} directory ! ! Skipping process {}.",
                        task,
                        name
                    );
                    continue;
                }
            };

            for t in taskdir.flatten() {
                let tname = t.file_name().to_string_lossy().into_owned();
                if tname == "." || tname == ".." {
                    continue;
                }
                if !tname.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    unhide_core::clear_errno();
                    warnln!(
                        self.out,
                        verbose,
                        "Not a thread ID ({}) in {}.",
                        tname,
                        task
                    );
                    continue;
                }
                let procpids = atoi(&tname);
                if tname != name {
                    // 线程（LWP != 主线程）
                    if self.checkps(procpids, PS_THREAD) {
                        continue;
                    }
                    self.printbadpid(procpids);
                } else {
                    // 主线程/进程本身
                    if self.checkps(procpids, PS_PROC) {
                        continue;
                    }
                    self.printbadpid(procpids);
                }
            }
        }
    }
}
