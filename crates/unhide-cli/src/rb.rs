//! unhide_rb 子命令：ruby unhide.rb 的移植（玩具/proof of fake，仅 Linux）。
//! 对应 unhide_rb.c。
//!
//! 忠实保留原版的瑕疵：检测器看返回值 != -1（非 errno）、status 里用小写
//! "ppid:" 匹配（真实 Linux 是 "PPid:"，故 /proc_parent 检测器几乎总是 UNKNOWN）、
//! ps 行用固定偏移 7 取命令列。用 HashMap 替代原版 ~192MB 的静态数组（等价）。

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::mem;

const UNHIDE_RB: &str = "ps axhHo lwp,cmd";
const DEFAULT_MAX_PID: i32 = 8388608;

const PID_DETECTORS: [&str; 11] = [
    "ps",
    "/proc ",
    "/proc_tasks ",
    "/proc_parent",
    "getsid()",
    "getpgid()",
    "getpriority()",
    "sched_getparam()",
    "sched_getaffinity()",
    "sched_getscheduler()",
    "sched_rr_get_interval()",
];

// 检测器索引。
const N_PS: usize = 0;
const N_PROC: usize = 1;
const N_PROC_TASK: usize = 2;
const N_PROC_PARENT: usize = 3;

const TRUE: i32 = 1;
const FALSE: i32 = 0;
const UNKNOWN: i32 = -1;

struct Rb {
    proc_parent: HashSet<i32>,
    proc_tasks: HashMap<i32, String>,
    ps_pids: HashMap<i32, String>,
    messages_pids: HashMap<i32, String>,
    ps_count: i32,
    maxpid: i32,
    message: String,
}

fn puts(s: &str) {
    print!("{}\n", s);
    let _ = io::stdout().flush();
}

fn parse_leading_int(s: &str) -> i32 {
    let t = s.trim_start();
    let digits: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or(0)
}

fn header() -> String {
    let mut s = String::new();
    s.push_str("Unhide_rb 20240509\n");
    s.push_str("Copyright © 2013-2024 Yago Jesus & Patrick Gouin\n");
    s.push_str("License GPLv3+\u{a0}: GNU GPL version 3 or later\n");
    s.push_str("http://www.unhide-forensics.info\n\n");
    s.push_str("NOTE : This version of unhide_rb is for systems using Linux >= 2.6 \n\n");
    s.push_str("WARNING : \n");
    s.push_str("TL;DR : This tool is a P.O.F. (proof of fake).\n");
    s.push_str("        It's not maintained any more.\n\n");
    s.push_str("        DON'T USE IT for serious work.\n\n");
    s.push_str(" Back in time, the Dev of unhide.rb pretends that his tool, written in ruby\n");
    s.push_str(
        " do the same checks that unhide-linux, which is written in C, but is 10 times faster.\n",
    );
    s.push_str(" This was evidently false:\n");
    s.push_str(" - unhide.rb makes less tests,\n");
    s.push_str(" - unhide.rb tests are less accurate,\n");
    s.push_str(" - unhide.rb  only outputs minimal information about hidden processes,\n");
    s.push_str(" - unhide.rb finds lot of false positives when processes number is high,\n");
    s.push_str(" - unhide.rb finds lot of false positives when there are short live processes,\n");
    s.push_str(" - unhide.rb doesn't log results of tests,\n");
    s.push_str(" - and so on.\n");
    s.push_str(
        " In order to verify assertion about speed, I backported unhide.rb to C language,\n",
    );
    s.push_str(" in the more straight/dummy way:\n");
    s.push_str(
        " No optimisation, translation from line to line, exactly the same tests and treatments.\n",
    );
    s.push_str(" The result is native unhide_rb.\n");
    s.push_str(" It is ONE THOUSAND times faster that the original ruby unhide.rb\n\n");
    s.push_str(" SO, DON'T RELY NEITHER ON UNHIDE.RB NOR ON UNHIDE_RB, THEY ARE JUST TOYS ! \n");
    s.push_str(
        " For a quick but quite accurate test, use the command 'unhide-linux quick reverse'\n\n",
    );
    s
}

impl Rb {
    fn new() -> Self {
        Rb {
            proc_parent: HashSet::new(),
            proc_tasks: HashMap::new(),
            ps_pids: HashMap::new(),
            messages_pids: HashMap::new(),
            ps_count: 0,
            maxpid: DEFAULT_MAX_PID,
            message: String::new(),
        }
    }

    fn setup(&mut self, phase: i32) {
        if let Ok(procdir) = std::fs::read_dir("/proc") {
            for entry in procdir.flatten() {
                if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    continue;
                }

                // proc_parent：读 status 找小写 "ppid:"（忠实保留 bug，真实 Linux 不命中）。
                let status_path = format!("/proc/{}/status", name);
                if let Ok(content) = std::fs::read_to_string(&status_path) {
                    for line in content.lines() {
                        if line.starts_with("ppid:") {
                            let tmp_pid = parse_leading_int(&line[5..]);
                            self.proc_parent.insert(tmp_pid);
                        }
                    }
                }

                // proc_tasks：遍历 /proc/<pid>/task/<tid>/exe。
                let task_path = format!("/proc/{}/task/", name);
                if let Ok(taskdir) = std::fs::read_dir(&task_path) {
                    for t in taskdir.flatten() {
                        let tname = t.file_name().to_string_lossy().into_owned();
                        if !tname.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                            continue;
                        }
                        let myexe = format!("{}{}/exe", task_path, tname);
                        if let Ok(target) = std::fs::read_link(&myexe) {
                            let tid = parse_leading_int(&tname);
                            if phase == 2 {
                                self.proc_tasks
                                    .insert(tid, target.to_string_lossy().into_owned());
                            } else {
                                self.proc_tasks.insert(tid, String::new());
                            }
                        }
                    }
                }
            }
        }

        // ps_pids：跑 `ps axhHo lwp,cmd`。
        if let Some(lines) = unhide_core::run_pipe_lines(UNHIDE_RB) {
            for myline in &lines {
                if myline.starts_with('\n') || myline.is_empty() {
                    continue;
                }
                let mypid = parse_leading_int(myline);
                // 用固定偏移 7 取命令列；排除我们自己 spawn 的 ps。
                let after7 = myline.get(7..).unwrap_or("");
                if !after7.contains(UNHIDE_RB) {
                    self.ps_count += 1;
                    if phase == 2 {
                        let stripped = myline.trim_end_matches([' ', '\n', '\r', '\t']);
                        let cmd = stripped.get(7..).unwrap_or("");
                        self.ps_pids.insert(mypid, cmd.to_string());
                    } else {
                        self.ps_pids.insert(mypid, String::new());
                    }
                }
            }
        }
    }

    fn read_pid_max(&mut self) {
        match std::fs::read_to_string("/proc/sys/kernel/pid_max") {
            Err(e) => {
                print!(
                    "[*] Error: cannot get current maximum PID: {}\n",
                    e.raw_os_error()
                        .map(unhide_core::strerror)
                        .unwrap_or_else(|| e.to_string())
                );
            }
            Ok(s) => {
                // 等价 fscanf("%d")：取前导整数（容忍尾部换行）。值 >=1 才采用。
                let v = parse_leading_int(&s);
                if v >= 1 {
                    self.maxpid = v;
                } else {
                    print!(
                        "[*] cannot get current maximum PID: Error parsing /proc/sys/kernel/pid_max format\n"
                    );
                }
            }
        }
    }

    fn get_suspicious_pids(&mut self, pid_num: i32) -> bool {
        let (pid_min, pid_max) = if pid_num == -1 {
            self.read_pid_max();
            print!("pid_max : {}\n", self.maxpid);
            let _ = io::stdout().flush();
            (1, self.maxpid)
        } else {
            (pid_num, pid_num)
        };

        let mut found_p = false;
        for my_pid in pid_min..=pid_max {
            let mut pid_exists = [FALSE; 11];
            let mut proc_exe = String::new();

            // N_PS
            pid_exists[N_PS] = if self.ps_pids.contains_key(&my_pid) {
                TRUE
            } else {
                FALSE
            };

            // N_PROC
            let procpath = format!("/proc/{}", my_pid);
            let is_dir = std::fs::metadata(&procpath)
                .map(|m| m.is_dir())
                .unwrap_or(false);
            if is_dir {
                pid_exists[N_PROC] = TRUE;
                match std::fs::read_link(format!("{}/exe", procpath)) {
                    Ok(target) => proc_exe = target.to_string_lossy().into_owned(),
                    Err(_) => proc_exe = "unknown exe".to_string(),
                }
            } else {
                pid_exists[N_PROC] = FALSE;
            }

            // N_PROC_TASK
            pid_exists[N_PROC_TASK] = if self.proc_tasks.contains_key(&my_pid) {
                TRUE
            } else {
                FALSE
            };

            // N_PROC_PARENT（命中→TRUE，否则 UNKNOWN）
            pid_exists[N_PROC_PARENT] = if self.proc_parent.contains(&my_pid) {
                TRUE
            } else {
                UNKNOWN
            };

            // 5 个系统调用 + 2 个 sched，全部看返回值 != -1（忠实保留，非 errno）。
            unsafe {
                pid_exists[4] = i32::from(libc::getsid(my_pid) != -1);
                pid_exists[5] = i32::from(libc::getpgid(my_pid) != -1);
                pid_exists[6] =
                    i32::from(libc::getpriority(libc::PRIO_PROCESS, my_pid as libc::id_t) != -1);
                let mut param: libc::sched_param = mem::zeroed();
                pid_exists[7] = i32::from(libc::sched_getparam(my_pid, &mut param) != -1);
                let mut mask: libc::cpu_set_t = mem::zeroed();
                pid_exists[8] = i32::from(
                    libc::sched_getaffinity(my_pid, mem::size_of::<libc::cpu_set_t>(), &mut mask)
                        != -1,
                );
                pid_exists[9] = i32::from(libc::sched_getscheduler(my_pid) != -1);
                let mut tp: libc::timespec = mem::zeroed();
                pid_exists[10] = i32::from(libc::sched_rr_get_interval(my_pid, &mut tp) != -1);
            }

            // consensus：以第一个非 UNKNOWN 为基准，任一矛盾即可疑。
            let mut suspicious = false;
            let mut consensus = UNKNOWN;
            for &v in pid_exists.iter() {
                if consensus == UNKNOWN {
                    consensus = v;
                }
                if v == UNKNOWN {
                    continue;
                }
                if consensus == FALSE {
                    if v == TRUE {
                        suspicious = true;
                        break;
                    }
                } else if v == FALSE {
                    suspicious = true;
                    break;
                }
            }

            if suspicious {
                found_p = true;
                let mut message = format!("Suspicious PID {:5}:", my_pid);
                for (index, &v) in pid_exists.iter().enumerate() {
                    if v == UNKNOWN {
                        continue;
                    }
                    let mut description = String::new();
                    if pid_num != -1 {
                        if index == N_PS {
                            if let Some(c) = self.ps_pids.get(&my_pid) {
                                description = c.clone();
                            }
                        } else if index == N_PROC_TASK {
                            if let Some(c) = self.proc_tasks.get(&my_pid) {
                                description = c.clone();
                            }
                        } else if index == N_PROC {
                            description = proc_exe.clone();
                        }
                    }
                    let seen = if v != 0 { "Seen by" } else { "Not seen by" };
                    message.push_str(&format!(
                        "\n  {} {} {}",
                        seen, PID_DETECTORS[index], description
                    ));
                }
                self.message = message;
                if pid_num == -1 {
                    self.messages_pids.insert(my_pid, self.message.clone());
                }
            }
        }
        found_p
    }
}

fn sysinfo_procs() -> i32 {
    unsafe {
        let mut info: libc::sysinfo = mem::zeroed();
        libc::sysinfo(&mut info);
        info.procs as i32
    }
}

pub fn run() -> i32 {
    print!("{}", header());
    let _ = io::stdout().flush();

    if unsafe { libc::getuid() } != 0 {
        let prog = std::env::args()
            .next()
            .unwrap_or_else(|| "unhide".to_string());
        print!("You must be root to run {} !\n", prog);
        let _ = io::stdout().flush();
        return 1;
    }

    puts("Scanning for hidden processes...");

    let mut rb = Rb::new();
    rb.setup(1);

    let procs = sysinfo_procs();
    if rb.ps_count != procs {
        puts("ps and sysinfo() process count mismatch:\n");
        print!("  ps: {} processes\n", rb.ps_count);
        print!("  sysinfo(): {} processes\n", procs);
        let _ = io::stdout().flush();
    }

    puts("Phase 1...");
    let phase1_ko = rb.get_suspicious_pids(-1);

    // phase1 把 ps_pids/proc_tasks 当布尔哨兵用过，清空（messages_pids 保留）。
    rb.ps_pids.clear();
    rb.proc_tasks.clear();

    let mut found_something = false;
    if phase1_ko {
        puts("Phase 2...");
        rb.setup(2);
        let pids: Vec<i32> = rb
            .messages_pids
            .keys()
            .copied()
            .filter(|&i| i >= 1)
            .collect();
        // 原版按 i 从 1..maxpid 升序遍历 messages_pids。
        let mut pids = pids;
        pids.sort_unstable();
        for i in pids {
            if rb.get_suspicious_pids(i) {
                found_something = true;
                puts(&rb.message.clone());
            }
        }
    }

    if found_something {
        -2
    } else {
        puts("No hidden processes found!");
        0
    }
}
