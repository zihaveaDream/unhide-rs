//! unhide-gui：UnHide 的图形前端（Rust/egui 复刻 unhideGui.py）。
//!
//! 本质是命令构造器 + 执行器：勾选选项/测试 → 拼出 `unhide linux ...` /
//! `unhide tcp ...` 命令 → 在输出窗口里流式显示其 stdout。
//! 忠实保留原版：无菜单、无 About、无 root 检查、compound↔elementary 联动。

#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

/// 一个带命令行参数的选项复选框。
struct OptItem {
    label: String,
    arg: String,
    tip: String,
    checked: bool,
}

/// 一个测试复选框（compound 或 elementary）。
struct TestItem {
    name: String,
    tip: String,
    checked: bool,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Linux,
    Tcp,
}

struct App {
    tab: Tab,
    lin_opts: Vec<OptItem>,
    compound: Vec<TestItem>,
    elementary: Vec<TestItem>,
    tcp_opts: Vec<OptItem>,
    command: String,
    unhide_path: String,
    output: Arc<Mutex<String>>,
    show_output: bool,
}

/// compound → 其展开的 elementary 集合（对应 TestGroupList）。
fn group_of(name: &str) -> &'static [&'static str] {
    match name {
        "brute" => &["checkbrute"],
        "proc" => &["checkproc"],
        "procall" => &["checkchdir", "checkopendir", "checkproc", "checkreaddir"],
        "procfs" => &["checkchdir", "checkopendir", "checkreaddir"],
        "quick" => &["checkquick"],
        "reverse" => &["checkreverse"],
        "sys" => &[
            "checkRRgetinterval",
            "checkgetaffinity",
            "checkgetparam",
            "checkgetpgid",
            "checkgetprio",
            "checkgetsched",
            "checkgetsid",
            "checkkill",
            "checknoprocps",
        ],
        _ => &[],
    }
}

fn opt(label: &str, arg: &str, tip: &str) -> OptItem {
    OptItem {
        label: label.to_string(),
        arg: arg.to_string(),
        tip: tip.to_string(),
        checked: false,
    }
}

fn test(name: &str, tip: &str) -> TestItem {
    TestItem {
        name: name.to_string(),
        tip: tip.to_string(),
        checked: false,
    }
}

/// 探测 unhide 可执行文件路径：优先与本 GUI 同目录的 `unhide`，否则用 PATH。
fn discover_unhide() -> String {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join(if cfg!(windows) {
                "unhide.exe"
            } else {
                "unhide"
            });
            if cand.is_file() {
                return cand.to_string_lossy().into_owned();
            }
        }
    }
    "unhide".to_string()
}

impl Default for App {
    fn default() -> Self {
        let lin_opts = vec![
            opt("Version", "-V", "Show version and exit"),
            opt(
                "Verbose",
                "-v",
                "Be verbose, display warning message (default : don't display).  This option may be repeated more than once.",
            ),
            opt("Help", "-h", "Display help"),
            opt(
                "More checks",
                "-m",
                "Do more checks. This option has only effect for the procfs, procall, checkopendir and checkchdir tests.\nImplies -v",
            ),
            opt("Alternate sysinfo", "-r", "Use alternate version of sysinfo check in standard tests"),
            opt("Log result", "-f", "Write a log file (unhide-linux.log) in the current directory."),
            opt("Log result", "-o", "Write a log file (unhide-linux.log) in the current directory."),
            opt("Double check", "-d", "Do a double check in brute test to avoid false positive."),
            opt("Human friendly", "-H", "Output a slightlu human friendlier result"),
        ];
        let compound = vec![
            test("brute", "The brute technique consists of bruteforcing the all process IDs.\nThis technique is only available with version unhide-linux."),
            test("proc", "The proc technique consists of comparing /proc with the output of /bin/ps."),
            test("procall", "The procall technique combinates proc and procfs tests.\nThis technique is only available with version unhide-linux."),
            test("procfs", "The procfs technique consists of comparing information gathered from /bin/ps with information gathered by walking in the procfs.\nWith -m option, this test makes more checks, see checkchdir test."),
            test("quick", "The quick technique combines the proc, procfs and sys techniques in a quick way. It's about 20 times faster but may give more false positives."),
            test("reverse", "The reverse technique consists of verifying that all threads seen by ps are also seen in procfs and by system calls."),
            test("sys", "The sys technique consists of comparing information gathered from /bin/ps with information gathered from system calls."),
        ];
        let elementary = vec![
            test("checkRRgetinterval", "Compare /bin/ps with the result of sched_rr_get_interval()."),
            test("checkbrute", "Bruteforce all process IDs."),
            test("checkchdir", "Compare /bin/ps with information gathered by making chdir() in the procfs.\nWith -m, also verify that the thread appears in its 'leader process' threads list."),
            test("checkgetaffinity", "Compare /bin/ps with the result of sched_getaffinity()."),
            test("checkgetparam", "Compare /bin/ps with the result of sched_getparam()."),
            test("checkgetpgid", "Compare /bin/ps with the result of getpgid()."),
            test("checkgetprio", "Compare /bin/ps with the result of getpriority()."),
            test("checkgetsched", "Compare /bin/ps with the result of sched_getscheduler()."),
            test("checkgetsid", "Compare /bin/ps with the result of getsid()."),
            test("checkkill", "Compare /bin/ps with the result of kill().\nNote : no process is really killed by this test."),
            test("checknoprocps", "Compare the result of each of the system functions. No comparison is done against /proc or ps."),
            test("checkopendir", "Compare /bin/ps with information gathered by making opendir() in the procfs."),
            test("checkproc", "Compare /proc with the output of /bin/ps."),
            test("checkquick", "Combine proc, procfs and sys techniques in a quick way."),
            test("checkreaddir", "Compare /bin/ps with information gathered by making readdir() in /proc and /proc/pid/task."),
            test("checkreverse", "Verify that all threads seen by ps are also seen in procfs and by system calls."),
            test("checksysinfo", "Compare the number of process seen by /bin/ps with sysinfo() system call."),
            test("checksysinfo2", "Alternate version of checksysinfo. May work better on RT/preempt kernels."),
            test("checksysinfo3", "Alternate version of checksysinfo."),
        ];
        let tcp_opts = vec![
            opt("Help", "-h", "Display help"),
            opt("Quiet", "--brief", "Don't display warning messages"),
            opt("fuser", "-f", "On Linux, display fuser output (if available). On FreeBSD displays the output of sockstat"),
            opt("lsof", "-l", "Display lsof output (if available)"),
            opt("netstat", "-n", "Use /bin/netstat instead of /sbin/ss."),
            opt("Server", "-s", "Use a very quick strategy of scanning (for servers)."),
            opt("Log", "-o", "Write a log file."),
            opt("Version", "-V", "Show version and exit"),
            opt("Verbose", "-v", "Be verbose, display warning message"),
            opt("Human friendly", "-H", "Output a slightlu human friendlier result"),
        ];

        let mut app = App {
            tab: Tab::Linux,
            lin_opts,
            compound,
            elementary,
            tcp_opts,
            command: String::new(),
            unhide_path: discover_unhide(),
            output: Arc::new(Mutex::new(String::new())),
            show_output: false,
        };
        app.gen_command();
        app
    }
}

impl App {
    /// compound 被勾选/取消时，同步其所有 elementary。
    fn sync_from_compound(&mut self, name: &str, val: bool) {
        let group = group_of(name);
        for e in &mut self.elementary {
            if group.iter().any(|g| *g == e.name) {
                e.checked = val;
            }
        }
    }

    /// elementary 变化时，回填/取消相关 compound。
    fn sync_from_elementary(&mut self, name: &str, val: bool) {
        if !val {
            for c in &mut self.compound {
                if group_of(&c.name).iter().any(|g| *g == name) {
                    c.checked = false;
                }
            }
        } else {
            let mut to_check = Vec::new();
            for c in &self.compound {
                let g = group_of(&c.name);
                if g.iter().any(|x| *x == name) {
                    let all = g
                        .iter()
                        .all(|en| self.elementary.iter().any(|e| e.name == *en && e.checked));
                    if all {
                        to_check.push(c.name.clone());
                    }
                }
            }
            for c in &mut self.compound {
                if to_check.contains(&c.name) {
                    c.checked = true;
                }
            }
        }
    }

    /// 拼出命令字符串（用于显示与执行）。
    fn build_argv(&self) -> Vec<String> {
        let mut v = vec![self.unhide_path.clone()];
        match self.tab {
            Tab::Linux => {
                v.push("linux".to_string());
                for o in &self.lin_opts {
                    if o.checked {
                        v.push(o.arg.clone());
                    }
                }
                let mut covered: Vec<&str> = Vec::new();
                for c in &self.compound {
                    if c.checked {
                        v.push(c.name.clone());
                        for e in group_of(&c.name) {
                            covered.push(e);
                        }
                    }
                }
                for e in &self.elementary {
                    if e.checked && !covered.contains(&e.name.as_str()) {
                        v.push(e.name.clone());
                    }
                }
            }
            Tab::Tcp => {
                v.push("tcp".to_string());
                for o in &self.tcp_opts {
                    if o.checked {
                        v.push(o.arg.clone());
                    }
                }
            }
        }
        v
    }

    fn gen_command(&mut self) {
        self.command = self.build_argv().join(" ");
    }

    /// 后台执行命令，stdout 逐行写入共享缓冲并请求重绘。
    fn run_command(&mut self, ctx: &egui::Context) {
        let argv = self.build_argv();
        let out = self.output.clone();
        *out.lock().unwrap() = String::new();
        self.show_output = true;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let mut cmd = Command::new(&argv[0]);
            cmd.args(&argv[1..]).stdout(Stdio::piped());
            match cmd.spawn() {
                Ok(mut child) => {
                    if let Some(so) = child.stdout.take() {
                        let reader = BufReader::new(so);
                        for line in reader.lines().map_while(Result::ok) {
                            {
                                let mut buf = out.lock().unwrap();
                                buf.push_str(&line);
                                buf.push('\n');
                            }
                            ctx.request_repaint();
                        }
                    }
                    let _ = child.wait();
                }
                Err(e) => {
                    out.lock()
                        .unwrap()
                        .push_str(&format!("Failed to run command: {}\n", e));
                }
            }
            ctx.request_repaint();
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut changed_compound: Option<(String, bool)> = None;
        let mut changed_elem: Option<(String, bool)> = None;
        let mut other_changed = false;
        let mut do_run = false;
        let mut do_copy = false;

        egui::CentralPanel::default().show(ctx, |ui| {
            // Tab 选择。
            ui.horizontal(|ui| {
                if ui
                    .selectable_label(self.tab == Tab::Linux, "Unhide-linux")
                    .clicked()
                {
                    self.tab = Tab::Linux;
                    other_changed = true;
                }
                if ui
                    .selectable_label(self.tab == Tab::Tcp, "Unhide-tcp")
                    .clicked()
                {
                    self.tab = Tab::Tcp;
                    other_changed = true;
                }
            });
            ui.separator();

            match self.tab {
                Tab::Linux => {
                    ui.horizontal_top(|ui| {
                        ui.group(|ui| {
                            ui.vertical(|ui| {
                                ui.label("Options");
                                for o in &mut self.lin_opts {
                                    if ui
                                        .checkbox(&mut o.checked, &o.label)
                                        .on_hover_text(&o.tip)
                                        .changed()
                                    {
                                        other_changed = true;
                                    }
                                }
                            });
                        });
                        ui.group(|ui| {
                            ui.vertical(|ui| {
                                ui.label("Compound Tests");
                                for c in &mut self.compound {
                                    if ui
                                        .checkbox(&mut c.checked, &c.name)
                                        .on_hover_text(&c.tip)
                                        .changed()
                                    {
                                        changed_compound = Some((c.name.clone(), c.checked));
                                    }
                                }
                            });
                        });
                        ui.group(|ui| {
                            ui.vertical(|ui| {
                                ui.label("Elementary Tests");
                                // 两列布局：前 10 / 后 9。
                                ui.horizontal_top(|ui| {
                                    ui.vertical(|ui| {
                                        for c in self.elementary.iter_mut().take(10) {
                                            if ui
                                                .checkbox(&mut c.checked, &c.name)
                                                .on_hover_text(&c.tip)
                                                .changed()
                                            {
                                                changed_elem = Some((c.name.clone(), c.checked));
                                            }
                                        }
                                    });
                                    ui.vertical(|ui| {
                                        for c in self.elementary.iter_mut().skip(10) {
                                            if ui
                                                .checkbox(&mut c.checked, &c.name)
                                                .on_hover_text(&c.tip)
                                                .changed()
                                            {
                                                changed_elem = Some((c.name.clone(), c.checked));
                                            }
                                        }
                                    });
                                });
                            });
                        });
                    });
                }
                Tab::Tcp => {
                    ui.group(|ui| {
                        ui.vertical(|ui| {
                            ui.label("Options");
                            for o in &mut self.tcp_opts {
                                if ui
                                    .checkbox(&mut o.checked, &o.label)
                                    .on_hover_text(&o.tip)
                                    .changed()
                                {
                                    other_changed = true;
                                }
                            }
                        });
                    });
                }
            }

            ui.separator();
            ui.group(|ui| {
                ui.label("Command Unhide");
                ui.add(
                    egui::TextEdit::singleline(&mut self.command.clone())
                        .desired_width(f32::INFINITY),
                );
                ui.horizontal(|ui| {
                    if ui.button("Run").clicked() {
                        do_run = true;
                    }
                    if ui.button("Generate").clicked() {
                        other_changed = true;
                    }
                    if ui.button("Copy to ClipBoard").clicked() {
                        do_copy = true;
                    }
                });
            });
        });

        // 应用联动并重新生成命令。
        if let Some((name, val)) = changed_compound.take() {
            self.sync_from_compound(&name, val);
            self.gen_command();
        }
        if let Some((name, val)) = changed_elem.take() {
            self.sync_from_elementary(&name, val);
            self.gen_command();
        }
        if other_changed {
            self.gen_command();
        }
        if do_copy {
            ctx.copy_text(self.command.clone());
        }
        if do_run {
            self.run_command(ctx);
        }

        // 输出窗口。
        if self.show_output {
            let mut open = true;
            egui::Window::new(self.command.clone())
                .open(&mut open)
                .default_size([700.0, 400.0])
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("Clear").clicked() {
                            *self.output.lock().unwrap() = String::new();
                        }
                    });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            // Read-only display of subprocess stdout; edits are discarded each frame.
                            let mut display_text = self.output.lock().unwrap().clone();
                            ui.add(
                                egui::TextEdit::multiline(&mut display_text)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace),
                            );
                        });
                });
            if !open {
                self.show_output = false;
            }
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("UnhideGUI")
            .with_inner_size([900.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native(
        "UnhideGUI",
        options,
        Box::new(|_cc| Ok(Box::<App>::default())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_mappings() {
        assert_eq!(group_of("proc"), &["checkproc"]);
        assert_eq!(group_of("sys").len(), 9);
        assert!(group_of("brute").contains(&"checkbrute"));
        assert_eq!(group_of("unknown").len(), 0);
    }

    #[test]
    fn compound_check_expands_and_dedups() {
        let mut app = App::default();
        app.unhide_path = "unhide".into();
        app.tab = Tab::Linux;
        for c in &mut app.compound {
            if c.name == "proc" {
                c.checked = true;
            }
        }
        app.sync_from_compound("proc", true);
        let argv = app.build_argv();
        assert_eq!(argv[0], "unhide");
        assert_eq!(argv[1], "linux");
        assert!(argv.contains(&"proc".to_string()));
        // checkproc 已被 proc 覆盖，不应重复出现。
        assert!(!argv.contains(&"checkproc".to_string()));
    }

    #[test]
    fn unchecking_elementary_unchecks_compound() {
        let mut app = App::default();
        for c in &mut app.compound {
            if c.name == "procfs" {
                c.checked = true;
            }
        }
        app.sync_from_compound("procfs", true);
        assert!(app
            .elementary
            .iter()
            .filter(|e| ["checkchdir", "checkopendir", "checkreaddir"].contains(&e.name.as_str()))
            .all(|e| e.checked));

        for e in &mut app.elementary {
            if e.name == "checkchdir" {
                e.checked = false;
            }
        }
        app.sync_from_elementary("checkchdir", false);
        assert!(
            !app.compound
                .iter()
                .find(|c| c.name == "procfs")
                .unwrap()
                .checked
        );
    }

    #[test]
    fn tcp_argv_uses_tcp_subcommand() {
        let mut app = App::default();
        app.unhide_path = "unhide".into();
        app.tab = Tab::Tcp;
        for o in &mut app.tcp_opts {
            if o.arg == "-s" {
                o.checked = true;
            }
        }
        let argv = app.build_argv();
        assert_eq!(argv[0], "unhide");
        assert_eq!(argv[1], "tcp");
        assert!(argv.contains(&"-s".to_string()));
    }
}
