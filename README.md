# linuxauditmgr

A small **CMake + wxWidgets (C++26)** desktop tool for reading Linux audit
(`auditd`) logs in a human-readable way, with live monitoring.

## Why this exists

This project started for two reasons:

1. **The Linux audit log is hard to read.** The raw log is awkward: fields like
   `proctitle` are hex-encoded, identities are numeric (`uid=1000`), syscalls
   are numbers, and a single logical event is split across several `type=`
   lines. This tool parses and groups those records, decodes the encoded
   fields, and prefers the kernel's *enriched* resolved values (`SYSCALL=read`,
   `AUID="sigsegv"`, …) when present.

2. **Maintaining complex AppArmor profiles by log profiling is painful.** The
   usual workflow is to run the Python `aa-` userspace tools (`aa-logprof` /
   `aa-genprof`) against the audit log, but in practice a multitude of bugs and
   rough edges in those tools makes that difficult and unreliable on large,
   complex profiles. So the AppArmor tab grew up alongside the log viewer: it
   correlates the audit log's `DENIED`/`ALLOWED` events directly with the
   profiles, and lets you edit, validate and normalize profiles from the same
   place — using the audit log you can already read clearly in the other tab.

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

A second tab has four sub-tabs: **Profiles**, **Denials**, **Allows** and
**Validation**. The
**Profiles** sub-tab parses a directory of
AppArmor profiles (e.g. `/etc/apparmor.d`) and shows, per profile, what access
it **gives** (allow rules) versus **takes** (explicit `deny` rules):

- One row per profile (nested child profiles / hats are shown indented), with
  its enforcement **mode** (enforce / complain) and a count of gives vs takes.
- Detail pane grouping the allowed and denied access by kind — files (with the
  permission string decoded, e.g. `rwk → read, write, lock`), capabilities,
  network, signal, ptrace, D-Bus, mount, etc. — plus the inherited abstraction
  includes and the source file:line.
- Substring filter over profile name, attachment path and rule text.
- Defaults to `/etc/apparmor.d` — the profiles the kernel actually loads — so
  reads, edits and reapplies all act on the real policy. Use **Browse…** to
  point it elsewhere, or set the `LINUXAUDITMGR_APPARMOR_DIR` environment
  variable to override the default (handy for testing against a copy).

> Most of `/etc/apparmor.d` is only readable by root, and writing/reapplying
> needs root too, so run the tool as root for real edits. To just inspect as a
> normal user, point it at a readable copy — e.g.
> `LINUXAUDITMGR_APPARMOR_DIR=~/apparmor.d` after
> `cp -a /etc/apparmor.d ~/apparmor.d` and making it readable.

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

Select a denial and use the **Actions...** menu (or right-click the row) to
edit the profile's source file, after a confirmation dialog showing the exact
change and file:

- for an **implicit** denial, **Allow** or **Deny** the access (adds a
  file/ptrace/signal allow or `deny` rule). The generated rule is shown in an
  editable field first, so you can adjust it — most usefully to widen the exact
  denied path into a glob (e.g. `/home/*/.cache/**`) before writing. When the
  new rule is a file rule, any existing file rules it covers are tidied up:
  overlapping permissions are removed from them, and a rule left with no
  permissions is deleted. This is done conservatively (same decision / `audit`
  / `owner` qualifier, and only existing rules with a concrete, glob-free path)
  so the effective policy is unchanged — the new, broader rule still covers
  whatever was trimmed away;
- for an **explicit-deny** denial, **Reverse this deny rule to allow** — the
  matched `deny` rule is rewritten in place with its `deny` qualifier removed
  (other qualifiers like `audit` are kept). Writes are crash-safe — the new contents are
written to a temp file in the same directory, fsync'd, re-parsed for validity,
and only then atomically `rename()`d over the original, so a crash mid-write
cannot corrupt or lose the profile.

By default the change is written to the file only; reload it into the kernel
with `apparmor_parser -r` for it to take effect. When the tool runs as **root**,
the **Reapply profile (apparmor_parser -r)** toggle (enabled and on by default
only for uid 0) makes it reload the edited profile into the kernel immediately
after writing, reporting the parser's output if it fails. Run as a normal user
the toggle is disabled and labelled *(needs root)*.

The **Allows** sub-tab is the mirror image of Denials: it shows the AppArmor
`ALLOWED` events from the loaded log (logged in complain mode, or by an `audit`
allow rule), aggregated and correlated with the profiles' allow rules:

- **allowed by rule** — an allow rule in the profile matches (shown in the
  detail pane; if it's not in the profile file it comes from an abstraction);
- **complain-mode only** — nothing permits this, so it is allowed *only* because
  the profile is in complain mode and **would be denied once it enforces**.

The complain-mode-only entries are the actionable ones: select one and use the
**Actions...** menu to add the allow rule (same editable dialog and crash-safe
write as Denials), so the access keeps working after you switch the profile back
to enforce.

The **Validation** sub-tab checks the profile files with the real
`apparmor_parser` tool — `apparmor_parser -Q --skip-cache <file>` compiles each
profile (resolving its includes) without loading it into the kernel or touching
the policy cache, so it works as a normal user. Press **Validate profiles** and
it lists the files that fail, with the parser's error message; select one for
the full output. Validation spawns one parser per file, so it runs on a
background thread with a live progress count and never freezes the UI.

For the files that *pass*, it also flags any whose rules are not in canonical
form (status **needs normalization**). Normalizing a profile:

- sorts rules the way the apparmor utils' `get_clean()` does — by kind, then
  deny rules before allow rules, then by the rendered rule text, which keeps
  all `owner` rules grouped together (after the non-owner ones), with blank
  lines between groups;
- merges plain file rules for the same path (combining their permissions) —
  exec-transition rules and quoted paths are kept verbatim rather than rebuilt,
  so a path is never re-quoted or re-escaped; and
- removes exact-duplicate rules.

The normalized output is re-checked with `apparmor_parser` before it replaces
the file. It aims to match the apparmor utils' formatting but is best-effort,
which is why the diff is always shown first.

Select a normalizable profile to see the exact **diff** in the detail pane, then
**Normalize selected...** writes it (crash-safely). The file preamble, each
profile's header, its `include` statements (with `local/` overrides kept last)
and any nested child profiles are preserved verbatim; only the rule lines are
rewritten, so **comments inside a profile body are dropped** — which is why the
diff is shown first. The normalized text is re-checked with `apparmor_parser`
before it replaces the file, and normalization never changes the effective
policy.

> As a normal user the root-only (`0600`) profiles under `/etc/apparmor.d`
> cannot be read, so they show up as read errors; run as root (or validate a
> readable copy) to check the whole set.

## Build

Requires a C++26 compiler (GCC 15+/Clang 19+), CMake ≥ 3.28, and
wxWidgets 3.2 (`core`, `base`).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/linuxauditmgr
```

## Install

Install rules follow the GNU conventions (via `GNUInstallDirs`) and honour
`CMAKE_INSTALL_PREFIX` (default `/usr/local`) and `DESTDIR`:

```sh
cmake --install build                 # -> $prefix/bin, share/applications, …
cmake --install build --prefix /usr   # override the prefix
DESTDIR=/tmp/pkg cmake --install build --prefix /usr   # staged/packaged install
```

It installs the `linuxauditmgr` binary to `${CMAKE_INSTALL_BINDIR}`, a desktop
entry to `${CMAKE_INSTALL_DATADIR}/applications`, a PolicyKit action to
`${CMAKE_INSTALL_DATADIR}/polkit-1/actions`, and this README to
`${CMAKE_INSTALL_DOCDIR}`.

### Running as root

Editing, validating and reapplying profiles under `/etc/apparmor.d` needs root.
The install ships a PolicyKit action (`org.radiotube.linuxauditmgr.run`) bound
to the installed binary, so you can launch it as root via `pkexec` with a normal
authentication dialog:

```sh
pkexec /usr/local/bin/linuxauditmgr   # path must match the installed prefix
```

The desktop entry also exposes this as a **Run as administrator (root)** action
(right-click the launcher). The action sets
`org.freedesktop.policykit.exec.allow_gui`, so `$DISPLAY`/`$XAUTHORITY` are
retained and the GUI works as root (via Xwayland on a Wayland session). The
`exec.path` annotation binds the action to the installed binary's absolute path,
so `pkexec` must be given that same path.

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
| `src/AppArmorDenials.*` | Denial/allow extraction, aggregation, glob match + rule correlation |
| `src/AppArmorEditor.*` | Rule generation + crash-safe insertion into profile files |
| `src/AppArmorValidator.*` | Validate profile files via `apparmor_parser -Q --skip-cache` |
| `src/AppArmorNormalizer.*` | Canonicalize a profile (sort/merge/dedupe rules) + line diff |
| `src/MainFrame.*`    | wxWidgets UI: notebook hosting the audit + AppArmor tabs |
| `src/AppArmorTab.*`  | AppArmor tab: inner notebook with the four sub-tabs |
| `src/AppArmorPanel.*` | wxWidgets UI for the AppArmor profile (gives/takes) sub-tab |
| `src/AppArmorEventsPanel.*` | wxWidgets UI for the Denials and Allows sub-tabs (by mode) |
| `src/AppArmorValidationPanel.*` | wxWidgets UI for the Validation sub-tab (background-threaded) |
| `src/App.cpp`        | `wxApp` entry point |

## Notes

- Sample/local logs (`audit.log*`) are git-ignored — they can contain sensitive
  host data and are large.
- The parser works on plain (`type=… msg=audit(…): …`) and ENRICHED-format
  logs (resolved fields after a `0x1d` separator); it does not require the
  `auditd` userspace libraries to be installed.
