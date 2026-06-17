# linuxauditmgr

A small **CMake + wxWidgets (C++26)** desktop tool for reading Linux audit
(`auditd`) logs in a human-readable way, with live monitoring.

The raw audit log is awkward to read: fields like `proctitle` are hex-encoded,
identities are numeric (`uid=1000`), syscalls are numbers, and a single logical
event is split across several `type=` lines. This tool parses and groups those
records, decodes the encoded fields, and prefers the kernel's *enriched*
resolved values (`SYSCALL=read`, `AUID="sigsegv"`, …) when present.

## Features

- **Read Current Logs** — parse an entire log file at once.
- **Start Live / Stop Live** — follow a log as it grows (handles rotation /
  truncation by reloading).
- One row per *logical event* (grouped by audit serial), with a decoded
  one-line summary. AppArmor `DENIED`/`ALLOWED` events are summarised with the
  operation, profile, and requested permission.
- Detail pane showing every record fully decoded, including resolved
  identities and a decoded `proctitle`/`EXECVE` command line.
- Substring filter and per-record-type filter for cutting through volume.
- Virtual list control, so tens of thousands of events stay responsive.

## Build

Requires a C++26 compiler (GCC 15+/Clang 19+), CMake ≥ 3.28, and
wxWidgets 3.2 (`core`, `base`).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/linuxauditmgr
```

## Usage

On launch the tool defaults to `/var/log/audit/audit.log` if readable
(usually needs root), otherwise a local `audit.log` if present. Use
**Browse…** to pick any audit log file, then **Read Current Logs** or
**Start Live**.

> Reading `/var/log/audit/audit.log` live normally requires root. To follow it
> without running the GUI as root you can grant read access to the file, or run
> the tool against a copy.

## Layout

| File | Responsibility |
|------|----------------|
| `src/AuditParser.*` | Record/Event model, line parsing, hex decoding, summaries |
| `src/LogTailer.*`   | Background read-all and live-follow with rotation handling |
| `src/MainFrame.*`   | wxWidgets UI (controls, virtual event list, detail pane) |
| `src/App.cpp`       | `wxApp` entry point |

## Notes

- Sample/local logs (`audit.log*`) are git-ignored — they can contain sensitive
  host data and are large.
- The parser works on plain (`type=… msg=audit(…): …`) and ENRICHED-format
  logs (resolved fields after a `0x1d` separator); it does not require the
  `auditd` userspace libraries to be installed.
