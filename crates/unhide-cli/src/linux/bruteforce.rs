//! brute 暴力遍历 PID 空间，对应 unhide-linux-bruteforce.c。
//!
//! 说明：原版 fork 段用 vfork()。vfork 在 Rust 中契约极脆弱，这里改用
//! fork()+_exit(0)（对"消耗一个 PID 号"这个测试目的完全等价、更安全）。
//! pthread 段用 std::thread 取 SYS_gettid 消耗一个 TID 号。两段串行执行
//! （同一时刻只有一个工作线程），与原版一致。

use unhide_core::die;

use super::{Ctx, PS_MORE, PS_PROC, PS_THREAD};

/// 初始化占位表：PID<301 为内核保留(0)，其余为自身索引值。
fn init_table(v: &mut [i32]) {
    for (i, slot) in v.iter_mut().enumerate() {
        *slot = if i < 301 { 0 } else { i as i32 };
    }
}

impl Ctx {
    pub fn brute(&mut self) {
        let maxpid = self.maxpid.max(0) as usize;
        let double = !self.brute_simple_check;

        self.out.msgln_str(
            0,
            "[*]Starting scanning using brute force against PIDS with fork()\n",
        );

        let mut allpids = vec![0i32; maxpid];
        let mut allpids2 = if double {
            vec![0i32; maxpid]
        } else {
            Vec::new()
        };

        init_table(&mut allpids);
        if double {
            init_table(&mut allpids2);
        }

        // ---- fork 段：逐个 fork 子进程消耗 PID 号 ----
        for _ in 301..maxpid {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe { libc::_exit(0) };
            }
            if pid > 0 {
                let u = pid as usize;
                if u < allpids.len() {
                    allpids[u] = 0;
                }
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
            }
        }
        if double {
            for _ in 301..maxpid {
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    unsafe { libc::_exit(0) };
                }
                if pid > 0 {
                    let u = pid as usize;
                    if u < allpids2.len() {
                        allpids2[u] = 0;
                    }
                    let mut status = 0;
                    unsafe { libc::waitpid(pid, &mut status, 0) };
                }
            }
        }

        self.scan(&allpids, &allpids2, double);

        // ---- pthread 段：逐个创建线程消耗 TID 号 ----
        self.out.msgln_str(
            0,
            "[*]Starting scanning using brute force against PIDS with pthread functions\n",
        );
        init_table(&mut allpids);
        if double {
            init_table(&mut allpids2);
        }

        for _ in 301..maxpid {
            self.thread_consume(&mut allpids);
        }
        if double {
            for _ in 301..maxpid {
                self.thread_consume(&mut allpids2);
            }
        }

        self.scan(&allpids, &allpids2, double);
    }

    /// 创建一个线程取其 TID 并在表中标记为已占用。
    fn thread_consume(&mut self, table: &mut [i32]) {
        let handle =
            std::thread::Builder::new().spawn(|| unsafe { libc::syscall(libc::SYS_gettid) as i32 });
        match handle {
            Err(_) => {
                die!(self.out, "Error: Cannot create thread ! Exiting.");
            }
            Ok(h) => match h.join() {
                Err(_) => {
                    die!(self.out, "Error : Cannot join thread ! Exiting.");
                }
                Ok(tid) => {
                    if tid >= 0 && (tid as usize) < table.len() {
                        table[tid as usize] = 0;
                    }
                }
            },
        }
    }

    /// 扫描占位表：仍持有初值的 PID（未能被我们占到）且 ps 看不到 → 隐藏。
    fn scan(&mut self, allpids: &[i32], allpids2: &[i32], double: bool) {
        for y in 0..allpids.len() {
            if allpids[y] != 0
                && (!double || allpids2[y] != 0)
                && !self.checkps(allpids[y], PS_PROC | PS_THREAD | PS_MORE)
            {
                self.printbadpid(allpids[y]);
            }
        }
    }
}
