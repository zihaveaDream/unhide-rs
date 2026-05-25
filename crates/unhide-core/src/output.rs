//! 输出与日志层，对应原版 unhide-output.c。

use std::fs::File;
use std::io::{self, Write};

use crate::{last_errno, strerror};

/// 持有可选的日志文件句柄。所有 msgln/warnln/die 都经它输出，
/// 以同时写 stdout/stderr 与日志文件。
pub struct Output {
    pub unlog: Option<File>,
}

impl Default for Output {
    fn default() -> Self {
        Self::new()
    }
}

impl Output {
    pub fn new() -> Self {
        Output { unlog: None }
    }

    /// 是否正在写日志（对应原版 logtofile==1 且 unlog 非空的语境）。
    pub fn logging(&self) -> bool {
        self.unlog.is_some()
    }

    /// 对应 msgln()：写 stdout，indent==1 时前置 `\t`，末尾追加 `\n`，并写日志。
    pub fn msgln_str(&mut self, indent: i32, s: &str) {
        let line = if indent == 1 {
            format!("\t{}\n", s)
        } else {
            format!("{}\n", s)
        };
        let mut so = io::stdout();
        let _ = so.write_all(line.as_bytes());
        let _ = so.flush();
        if let Some(f) = self.unlog.as_mut() {
            let _ = f.write_all(line.as_bytes());
        }
    }

    /// 对应 warnln()：verbose 为假则不输出；否则写 stderr，前缀 "Warning : "，
    /// errno!=0 时追加 ` [strerror]`，末尾 `\n`，并写日志。
    pub fn warn_str(&mut self, verbose: bool, errno: i32, s: &str) {
        if !verbose {
            return;
        }
        let mut msg = format!("Warning : {}", s);
        if errno != 0 {
            msg.push_str(&format!(" [{}]", strerror(errno)));
        }
        msg.push('\n');
        let mut se = io::stderr();
        let _ = se.write_all(msg.as_bytes());
        let _ = se.flush();
        if let Some(f) = self.unlog.as_mut() {
            let _ = f.write_all(msg.as_bytes());
        }
    }

    /// 对应 die()：写 stderr，前缀 "Error : "，errno 处理同上，然后 exit(1)。
    pub fn die_str(&mut self, errno: i32, s: &str) -> ! {
        let mut msg = format!("Error : {}", s);
        if errno != 0 {
            msg.push_str(&format!(" [{}]", strerror(errno)));
        }
        msg.push('\n');
        let mut se = io::stderr();
        let _ = se.write_all(msg.as_bytes());
        let _ = se.flush();
        if let Some(f) = self.unlog.as_mut() {
            let _ = f.write_all(msg.as_bytes());
        }
        std::process::exit(1);
    }

    /// 对应 init_log()：生成 `<basename>_YYYY-MM-DD_HHhMMmSSs.log`，写入 header
    /// 与一行 scan starting；hfriend 时该行也打到 stdout。失败则按原版打印 warning。
    pub fn open_log(&mut self, basename: &str, header: &str, hfriend: bool) {
        let tm = localtime_now();
        let filename = format!(
            "{}_{:04}-{:02}-{:02}_{:02}h{:02}m{:02}s.log",
            basename,
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        );
        match File::create(&filename) {
            Ok(mut f) => {
                let _ = f.write_all(header.as_bytes());
                let line = format!("\n{} scan starting at: {}\n", basename, time_string(&tm));
                let _ = f.write_all(line.as_bytes());
                if hfriend {
                    print!("{}", line);
                }
                self.unlog = Some(f);
            }
            Err(_) => {
                // 原版：warnln(1, NULL, "Unable to open log file (%s)!", filename)
                self.warn_str(
                    true,
                    last_errno(),
                    &format!("Unable to open log file ({})!", filename),
                );
            }
        }
        let _ = io::stdout().flush();
    }

    /// 对应 close_log()：写 scan ending 行（行前无 `\n`），hfriend 时也打 stdout，关闭。
    pub fn close_log(&mut self, basename: &str, hfriend: bool) {
        if self.unlog.is_none() {
            return;
        }
        let tm = localtime_now();
        let line = format!("{} scan ending at: {}\n", basename, time_string(&tm));
        if let Some(f) = self.unlog.as_mut() {
            let _ = f.write_all(line.as_bytes());
        }
        if hfriend {
            print!("{}", line);
        }
        let _ = io::stdout().flush();
        self.unlog = None; // 丢弃句柄即关闭文件
    }
}

/// 当前本地时间的 tm 结构（对应 localtime()）。
fn localtime_now() -> libc::tm {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        tm
    }
}

/// 对应 strftime(.., "%H:%M:%S, %F")。
fn time_string(tm: &libc::tm) -> String {
    format!(
        "{:02}:{:02}:{:02}, {:04}-{:02}-{:02}",
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday
    )
}
