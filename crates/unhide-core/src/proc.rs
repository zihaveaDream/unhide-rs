//! 外部命令执行与 /proc 相关助手。

use std::process::Command;

use crate::{last_errno, msgln, Output};

/// 用 `sh -c <cmd>` 执行一条命令（可含管道，等价原版 popen(cmd, "r")），
/// 返回 stdout 按行拆分后的结果（行内不含结尾换行）。
/// 返回 None 表示无法运行该命令（≈ popen 返回 NULL）。
pub fn run_pipe_lines(cmd: &str) -> Option<Vec<String>> {
    match Command::new("sh").arg("-c").arg(cmd).output() {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            Some(text.lines().map(|s| s.to_string()).collect())
        }
        Err(_) => None,
    }
}

/// 用 `sh -c <cmd>` 执行命令，流式逐行读取 stdout，每读一行调用 callback。
/// 返回 None 表示无法运行该命令（等价 popen 返回 NULL）。
/// 用于 checksysinfo 系列：原版以 stdbuf 强制 ps 逐行输出，并在读每行时
/// 重新采样 sysinfo()，须流式处理才能复刻该行为。
pub fn run_pipe_streamed(cmd: &str, mut callback: impl FnMut(&str)) -> Option<()> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        match line {
            Ok(l) => callback(&l),
            Err(_) => break,
        }
    }
    // 必须 reap 子进程：否则 sh/ps 仍计入随后的 sysinfo().procs，
    // 导致 checksysinfo 的 initial!=final 而误判为 "intermittent activity"。
    let _ = child.wait();
    Some(())
}

/// 对应 get_max_pid()：读 /proc/sys/kernel/pid_max；读失败/解析失败/值<1 时
/// 保留默认值并按原版打印对应警告。
pub fn get_max_pid(out: &mut Output, default: i32) -> i32 {
    const PATH: &str = "/proc/sys/kernel/pid_max";
    match std::fs::read_to_string(PATH) {
        Ok(s) => {
            // 等价 fscanf("%d")：取开头的整数。
            let parsed = s
                .trim_start()
                .split(|c: char| !c.is_ascii_digit() && c != '-')
                .next()
                .and_then(|t| t.parse::<i32>().ok());
            match parsed {
                Some(v) if v >= 1 => v,
                _ => {
                    msgln!(
                        out,
                        0,
                        "Warning : Cannot get current maximum PID, error parsing {} format. Using default value {}",
                        PATH,
                        default
                    );
                    default
                }
            }
        }
        Err(_) => {
            // 原版此处强制 verbose=1 打印。
            out.warn_str(
                true,
                last_errno(),
                &format!(
                    "Cannot read current maximum PID. Using default value {}",
                    default
                ),
            );
            default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_pipe_lines_splits_stdout() {
        let lines = run_pipe_lines("printf '10\\n20\\n30\\n'").unwrap();
        assert_eq!(lines, vec!["10", "20", "30"]);
    }

    #[test]
    fn run_pipe_lines_empty_output() {
        let lines = run_pipe_lines("true").unwrap();
        assert!(lines.is_empty());
    }
}
