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

### AppArmor profile viewer

A second tab has two sub-tabs. The **Profiles** sub-tab parses a directory of
AppArmor profiles (e.g. `/etc/apparmor.d`) and shows, per profile, what access
it **gives** (allow rules) versus **takes** (explicit `deny` rules):

- One row per profile (nested child profiles / hats are shown indented), with
  its enforcement **mode** (enforce / complain) and a count of gives vs takes.
- Detail pane grouping the allowed and denied access by kind — files (with the
  permission string decoded, e.g. `rwk → read, write, lock`), capabilities,
  network, signal, ptrace, D-Bus, mount, etc. — plus the inherited abstraction
  includes and the source file:line.
- Substring filter over profile name, attachment path and rule text.
- Defaults to a readable `~/apparmor.d` copy if present, otherwise
  `/etc/apparmor.d`; use **Browse…** to point it anywhere.

> Most of `/etc/apparmor.d` is only readable by root. Either run as root or
> point the tool at a readable copy
> (`cp -a /etc/apparmor.d ~/apparmor.d`, then make it readable by your user).

The **Denials** sub-tab cross-references the two: it pulls the AppArmor
`DENIED` events out of the audit log loaded in the Audit Log tab, aggregates
identical denials (by profile / operation / target / denied mask) with a count
and time span, and classifies each against the loaded profiles:

- **explicit deny rule** — an `audit deny` rule in the profile matches (the
  matching rule is shown in the detail pane);
- **implicit (no allow)** — nothing in the profile allowed the access, so it
  was denied by default. Most logged denials are implicit, because a plain
  `deny` rule is silent (only `audit deny` is logged);
- **profile not loaded** — the denied profile is not in the loaded directory.

Load a log in the Audit Log tab, then open the Denials sub-tab (it refreshes on
display, or use **Refresh**). Path matching understands AppArmor globs
(`*`, `**`, `?`, `{a,b}`).

## Build

Requires a C++26 compiler (GCC 15+/Clang 19+), CMake ≥ 3.28, and
wxWidgets 3.2 (`core`, `base`).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/linuxauditmgr
```

## Tests

The non-GUI core (parser + tailer) is covered by a Catch2 suite. Tests are
built by default at top level; run them with CTest:

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Fixtures in `tests/fixtures.h` are **anonymized** fragments from a real
enriched audit log (username, host paths, and kernel string scrubbed) that
preserve the structural quirks the parser must handle: the `0x1d` enriched
separator, quoted values, and hex-encoded `proctitle`/`exe` fields.

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
| `src/AuditParser.*`  | Record/Event model, line parsing, hex decoding, summaries |
| `src/LogTailer.*`    | Background read-all and live-follow with rotation handling |
| `src/AppArmorParser.*` | AppArmor profile model + parser (gives/takes, child profiles) |
| `src/AppArmorDenials.*` | Denial extraction, aggregation, glob match + deny-rule correlation |
| `src/MainFrame.*`    | wxWidgets UI: notebook hosting the audit + AppArmor tabs |
| `src/AppArmorTab.*`  | AppArmor tab: inner notebook with Profiles + Denials sub-tabs |
| `src/AppArmorPanel.*` | wxWidgets UI for the AppArmor profile (gives/takes) sub-tab |
| `src/AppArmorDenialsPanel.*` | wxWidgets UI for the AppArmor denials sub-tab |
| `src/App.cpp`        | `wxApp` entry point |

## Notes

- Sample/local logs (`audit.log*`) are git-ignored — they can contain sensitive
  host data and are large.
- The parser works on plain (`type=… msg=audit(…): …`) and ENRICHED-format
  logs (resolved fields after a `0x1d` separator); it does not require the
  `auditd` userspace libraries to be installed.
