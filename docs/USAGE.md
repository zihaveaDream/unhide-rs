# unhide-rs — User Manual

> 中文版：[USAGE_zh.md](USAGE_zh.md)

A practical guide to using the Rust port of UnHide: every subcommand, its
options, the test list, worked examples, common scenarios, and how to read the
output.

---

## 1. What it does and how

UnHide is a **forensic** tool. It finds processes and TCP/UDP ports that are
*present on the system but hidden from the usual tools* (`ps`, `ss`/`netstat`) —
the classic signature of a rootkit or a malicious kernel module.

The core idea is **cross-checking two independent views**:

- what `/bin/ps` (or `ss`/`netstat`) reports, versus
- what the kernel actually knows (via `/proc`, system calls, or by probing the
  PID / port space directly).

If the kernel sees a process/port that `ps`/`ss` does not, it is **hidden**.
If `ps` shows a thread the kernel cannot confirm, it is a **fake** (a tampered
`ps`). Because `ps` itself may be trojaned, the tool deliberately relies on
direct kernel queries for the "truth" side.

> **You must be root** to run `linux`, `tcp`, and `rb` (they need to read every
> `/proc` entry, make privileged syscalls, and bind every port).

---

## 2. Getting it

- **Pre-built**: download the archive for your platform from the GitHub Release
  (see the main README), unpack, and run `./unhide`.
- **Build**: `cd unhide-rs && cargo build --release -p unhide-cli`
  → binary at `unhide-rs/target/release/unhide`.

In the examples below `unhide` means that binary (use `sudo ./unhide ...` if it
is not on your `PATH`).

---

## 3. Command structure

The original shipped four separate programs; here they are subcommands of one
binary:

```
unhide linux [options] <test_list>     # hidden processes (Linux ≥ 2.6)
unhide posix <proc|sys>                # hidden processes (generic Unix)
unhide tcp   [options]                 # hidden TCP/UDP ports
unhide rb                              # toy port of unhide.rb (Linux)
unhide --help                          # list subcommands
unhide <sub> --help                    # help for a subcommand
```

---

## 4. `unhide linux` — hidden processes

### 4.1 Synopsis

```
sudo unhide linux [options] <test_list>
```

`<test_list>` is one or more test names (standard or elementary), e.g.
`quick reverse` or `sys procall brute`.

### 4.2 Options

| short | long | meaning |
|---|---|---|
| `-V` | `--version` | print the version header and exit |
| `-v` | `--verbose` | be verbose (show warnings); repeatable (`-vv`) |
| `-h` | `--help` | show help and exit |
| `-m` | `--morecheck` | extra checks (affects `procfs`, `checkopendir`, `checkchdir`); implies `-v` |
| `-r` | `--alt-sysinfo` | use the alternate sysinfo test in meta-tests (kept for compatibility; currently inert, as in the original) |
| `-f` | | write a log file `unhide-linux_<date>.log` in the current directory |
| `-o` | `--log` | same as `-f` |
| `-d` | `--brute-doublecheck` | double-check in the `brute` test (fewer false positives) |
| `-u` | | unbuffered subprocess stdout (prepends `stdbuf` to `ps`; useful when piped) |
| `-H` | `--human-frienly` | friendlier output (adds "no hidden process found" / "Done !" messages) |

> Root is checked **before** options, so even `unhide linux -h` as a non-root
> user prints the header then `Error : You must be root ...` — exactly like the
> original.

### 4.3 Test list

**Standard tests** (each expands into elementary tests):

| test | what it does |
|---|---|
| `proc` | compare `/proc` (via `stat`) against `ps` |
| `procfs` | compare `ps` against walking procfs (`chdir` + `opendir` + `readdir`) |
| `procall` | `proc` + `procfs` combined |
| `sys` | compare `ps` against system calls (`kill`, `getpriority`, `getpgid`, `getsid`, `sched_*`, …) |
| `quick` | combine proc/procfs/sys quickly — ~20× faster, may yield more false positives |
| `reverse` | verify every thread `ps` shows is also seen by the kernel (detects **fake** PIDs) |
| `brute` | brute-force the whole PID space via fork + threads (very thorough, very slow) |

**Elementary tests** (run one specific check): `checkproc`, `checkchdir`,
`checkopendir`, `checkreaddir`, `checkgetprio`, `checkgetpgid`, `checkgetsid`,
`checkgetaffinity`, `checkgetparam`, `checkgetsched`, `checkRRgetinterval`,
`checkkill`, `checknoprocps`, `checkquick`, `checkreverse`, `checkbrute`,
`checksysinfo`, `checksysinfo2`, `checksysinfo3`.

Notes:
- Tests run in a **fixed internal order**, not the order you type them.
- `sysinfo` tests are *not* part of `sys`/`quick` (they are prone to false
  positives); run them explicitly with `checksysinfo[2|3]`.
- `brute` is intentionally exhaustive: it sweeps PIDs `301..pid_max`
  (`pid_max` is `2^22` on 64-bit), so it can take a long time. Use it for a
  deep scan, not for quick triage.

### 4.4 Examples

```sh
# Quickest triage (combined fast scan)
sudo unhide linux quick

# Quick + verify ps wasn't tampered with
sudo unhide linux quick reverse

# Standard scan
sudo unhide linux sys proc

# Deep / thorough scan, double-checked, more checks, friendlier output
sudo unhide linux -m -d sys procall brute reverse

# Verbose, log to a file
sudo unhide linux -v -o sys

# A single elementary check
sudo unhide linux checkproc
```

### 4.5 Reading the output

A clean run prints the header, the start line of each test, and nothing else.
A hidden process is reported as:

```
Found HIDDEN PID: 12345
	Cmdline: "/usr/sbin/evil --daemon"
	Executable: "/usr/sbin/evil"
	Command: "evil"
	$USER=root
	$PWD=/
```

- `Cmdline` — first argument from `/proc/<pid>/cmdline` (`<none>` if empty).
- `Executable` — target of `/proc/<pid>/exe` (`<no link>` / `<nonexistant>` if
  unreadable).
- `Command` — `/proc/<pid>/comm`; shown as `[name]` for kernel threads.
- `$USER` / `$PWD` — from the process environment.

The `reverse` test instead reports tampering as:
`Found FAKE PID: 12345  Command = ...  not seen by N system function(s)`.

### 4.6 Exit codes

- `0` — no hidden/fake process found
- `1` — at least one hidden/fake process found (also: not root, or `argc < 2`)

Useful in scripts: `sudo unhide linux quick reverse || echo "SUSPICIOUS"`.

---

## 5. `unhide tcp` — hidden ports

### 5.1 Synopsis

```
sudo unhide tcp [options]
```

It scans **every** TCP and UDP port (1..65535), finds ports that are in use but
not reported by `ss` (or `netstat`), and reports them as hidden.

### 5.2 Options

| short | long | meaning |
|---|---|---|
| `-h` | `--help` | show help and exit |
| `-V` | | print version header and exit |
| `-v` | `--verbose` | show warnings (repeatable) |
| | `--brief` | suppress warnings (the default) |
| `-f` | `--fuser` | show `fuser` output for each hidden port (FreeBSD: `sockstat`) |
| `-l` | `--lsof` | show `lsof` output for each hidden port |
| `-n` | `--netstat` | use `netstat` instead of `ss` (slower on busy hosts) |
| `-s` | `--server` | very fast scan strategy for servers with many open ports |
| `-o` | `--log` | write a log file `unhide-tcp_<date>.log` |

### 5.3 Examples

```sh
# Default scan (uses ss on Linux)
sudo unhide tcp

# Show who owns each hidden port, verbose, log it
sudo unhide tcp -flov

# Fast strategy for a busy server, with lsof + fuser details
sudo unhide tcp -fls

# Force netstat instead of ss
sudo unhide tcp -n
```

### 5.4 Output and exit codes

A hidden port is reported as:

```
Found Hidden port that not appears in ss: 31337
	fuser reports :
	31337/tcp:            4242
	lsof reports :
	...
```

Exit code encodes what was found (handy for automation):

| code | meaning |
|---|---|
| `0` | nothing hidden |
| `4` | hidden **TCP** port(s) |
| `8` | hidden **UDP** port(s) |
| `12` | both TCP and UDP hidden ports |

`-s` (server) is hundreds of times faster than the `ss` method and ten-thousands
of times faster than `netstat` on hosts with many open ports; prefer it there.

---

## 6. `unhide posix` — generic Unix

For non-Linux Unix (and very old Linux). Takes exactly one argument:

```sh
sudo unhide posix proc     # /proc scan, cross-checked against ps
sudo unhide posix sys      # getpriority/getpgid/getsid scans
```

It is the legacy engine and **may produce more false positives** than
`unhide linux`; prefer `unhide linux` whenever you can. Hidden processes are
printed as `Found HIDDEN PID: <pid>` plus the command line.

---

## 7. `unhide rb` — the toy

```sh
sudo unhide rb
```

A faithful port of the old `unhide.rb`. Its own banner calls it a "proof of
fake" / toy and warns against relying on it (it makes fewer, less accurate
tests and is noisy with false positives). It runs two phases (`Phase 1` then a
`Phase 2` double-check) and prints `Suspicious PID <n>:` blocks listing which
detectors saw the PID. Exit code is `-2` (254) if anything was found, `0`
otherwise. Use `unhide linux quick reverse` instead for real work.

---

## 8. `unhide-gui` — graphical front-end

`unhide-gui` is a separate binary (desktop platforms only). It builds the
command for you and runs it:

1. Pick the **Unhide-linux** or **Unhide-tcp** tab.
2. Tick the options and tests. Ticking a *compound* test (e.g. `procfs`) ticks
   its elementary tests automatically, and vice-versa.
3. The assembled command is shown at the bottom; **Generate** refreshes it,
   **Copy to ClipBoard** copies it.
4. **Run** executes it and streams the output into a window (Close / Clear).

It invokes the same `unhide linux` / `unhide tcp` subcommands, so it must be
able to find the `unhide` binary (same directory, or on `PATH`). Run it as root
so the scans work.

---

## 9. Common scenarios (playbooks)

**Fast triage on a suspect host**
```sh
sudo unhide linux quick reverse      # processes (fast) + ps-integrity check
sudo unhide tcp -s                   # ports (fast server strategy)
```

**Thorough forensic sweep (collect evidence)**
```sh
sudo unhide linux -v -o -m -d sys procall brute reverse
sudo unhide tcp -flov                # log + fuser/lsof attribution
```
The `-o` flag leaves timestamped `.log` files in the current directory.

**Hunt only hidden listening ports, with attribution**
```sh
sudo unhide tcp -fl                  # who holds each hidden port
echo "exit=$?"                       # 4=TCP, 8=UDP, 12=both
```

**Check whether `ps` itself was tampered with**
```sh
sudo unhide linux reverse            # reports "FAKE PID" if ps lies
```

**Use in a monitoring script**
```sh
if ! sudo unhide linux -u quick reverse > /var/log/unhide.txt 2>&1; then
    alert "unhide flagged a hidden/fake process"
fi
```
`-u` makes subprocess output unbuffered, which is friendlier when piped.

---

## 10. Interpreting false positives

Forensic process/port scanning races against a live system. Expect occasional
false positives, especially:

- on **busy hosts** (processes/ports appearing and disappearing mid-scan),
- with the `sysinfo` tests (count-based; can over-report — that is why they are
  not in `sys`/`quick`),
- with `unhide posix` and `unhide rb` (less precise by design),
- short-lived processes (`bash` one-liners, build steps, `<defunct>` zombies).

Re-run with `-d` (double-check, for `brute`) and on a quiescent system to
separate real findings from churn. A *real* hidden process is reproducible and
typically has a suspicious or `<none>`/`<nonexistant>` cmdline/exe.

---

## 11. Differences from the original

- Four tools are now subcommands of one `unhide` binary (the original shipped
  `unhide-linux`, `unhide-posix`, `unhide-tcp`, `unhide_rb` separately). Options,
  test names, output, and exit codes are otherwise identical.
- `--help` / error text for invalid options is produced by the argument parser
  and may read slightly differently from the original `getopt` wording; option
  *semantics* and exit codes match.
- The GUI calls `unhide linux` / `unhide tcp` instead of the standalone
  binaries.

---

## 12. See also

- Manual pages of the original: `man/unhide.8`, `man/unhide-tcp.8`.
- Project README: [../README.md](../README.md) (中文：[../README_zh.md](../README_zh.md)).
