# Security Policy

`linuxauditmgr` reads the system audit log and can **read, edit, validate, and
reload AppArmor profiles** under `/etc/apparmor.d`, and ships a PolicyKit action
to run as **root** via `pkexec`. Because of that privileged surface, security
reports are taken seriously and responsible (coordinated) disclosure is
appreciated.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report privately, by email, to:

**Jan-Espen Oversand — <sigsegv@radiotube.org>**

(If you prefer, you may also use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository, where enabled.)

A useful report includes:

- a description of the issue and its security impact;
- the affected component (e.g. the audit-log parser, the AppArmor profile
  editor/normalizer, the `pkexec`/PolicyKit integration);
- the version or commit, your OS/distribution, and compiler/wxWidgets versions;
- steps to reproduce, and a minimal profile or log fragment if relevant
  (please redact anything sensitive);
- any suggested fix, if you have one.

You will normally get an acknowledgement within a few days. This is a
volunteer-maintained project, so fix timelines are best-effort; we will keep you
informed and coordinate a disclosure date with you.

## Areas of particular interest

Issues here have the highest impact and are especially welcome:

- **Privilege escalation** via the `pkexec` / PolicyKit action
  (`org.radiotube.linuxauditmgr.run`), e.g. ways to run arbitrary code as root
  through it.
- **Writing or corrupting files outside the loaded profiles directory**, or
  defeating the crash-safe write (temp → verify → atomic rename).
- **Generating an incorrect AppArmor rule** that weakens a profile while
  appearing to tighten it (rule generation, permission/mask mapping,
  subsumption/merge, or normalization producing a non-equivalent profile).
- **Parser memory-safety or denial-of-service** on hostile audit logs or
  profile files (the audit and AppArmor parsers).

## Scope

In scope: the code in this repository (the application, the audit/AppArmor
parsers, the profile editor/validator/normalizer, the CMake install, and the
desktop/PolicyKit integration files).

Out of scope: vulnerabilities in third-party dependencies themselves — report
those upstream — including wxWidgets, `apparmor_parser` and the AppArmor
userspace, PolicyKit/`pkexec`, and the C++ standard library/toolchain. A bug in
*how this project uses* one of those is in scope.

## Supported versions

The project is pre-1.0. Security fixes are made against the latest `master`;
please test against the current `master` before reporting.
