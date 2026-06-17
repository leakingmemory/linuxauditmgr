#pragma once

#include <string_view>

// Anonymized fragments derived from a real /var/log/audit/audit.log captured
// in ENRICHED format. Sensitive data has been scrubbed: the real username was
// replaced with "alice", real binary paths with /opt/app/... placeholders, and
// the host kernel string genericized. The structural details that the parser
// cares about are preserved verbatim:
//   * the 0x1d (GS) byte separating raw fields from resolved ones (\035 octal —
//     octal escapes stop after 3 digits, so it is safe before A-F/0-9),
//   * quoting of string values,
//   * hex-encoding of proctitle/exe fields (these specific hex strings, e.g.
//     "/bin/ps -e --format %P%p%a", contain nothing sensitive).

namespace fixtures {

// One logical event (serial 1001): an AppArmor ptrace denial with its SYSCALL
// (ENRICHED resolved fields after \035) and a hex-encoded PROCTITLE.
inline constexpr std::string_view kAvc =
    R"(type=AVC msg=audit(1700000001.123:1001): apparmor="DENIED" operation="ptrace" class="ptrace" profile="/opt/app/bin/launcher" pid=4242 comm="worker" requested_mask="readby" denied_mask="readby" peer="/opt/app/bin/peer")";

inline constexpr std::string_view kSyscall =
    "type=SYSCALL msg=audit(1700000001.123:1001): arch=c000003e syscall=0 "
    "success=yes exit=205 a0=5 a1=7ffcaabbccdd a2=400 a3=0 items=0 ppid=4000 "
    "pid=4242 auid=1000 uid=1000 gid=1000 euid=1000 comm=\"worker\" "
    "exe=\"/opt/app/bin/worker\" subj=unconfined key=(null)"
    "\035" "ARCH=x86_64 SYSCALL=read AUID=\"alice\" UID=\"alice\" GID=\"alice\"";

inline constexpr std::string_view kProctitle =
    "type=PROCTITLE msg=audit(1700000001.123:1001): "
    "proctitle=2F62696E2F7073002D65002D2D666F726D617400255025702561";
// decoded: "/bin/ps -e --format %P%p%a"

// A different event (serial 1002): EXECVE with quoted argv.
inline constexpr std::string_view kExecve =
    R"(type=EXECVE msg=audit(1700000002.500:1002): argc=3 a0="/opt/app/bin/launcher" a1="21.0.8+9-b1092.38" a2="211:214:218")";

// LOGIN with the glued "res=1\035UID=..." form seen in enriched logs.
inline constexpr std::string_view kLogin =
    "type=LOGIN msg=audit(1700000003.000:1003): pid=2266 uid=0 subj=unconfined "
    "old-auid=4294967295 auid=32 tty=(none) old-ses=4294967295 ses=1 res=1"
    "\035" "UID=\"root\" OLD-AUID=\"unset\" AUID=\"gdm\"";

// ANOM_ABEND whose exe is hex-encoded: "/usr/bin/gnome-shell (deleted)".
inline constexpr std::string_view kAnomAbend =
    "type=ANOM_ABEND msg=audit(1700000004.000:1004): auid=1000 uid=1000 gid=1000 "
    "ses=4 subj=unconfined pid=2902 comm=\"desktop-shell\" "
    "exe=2F7573722F62696E2F676E6F6D652D7368656C6C202864656C6574656429 sig=11 res=1"
    "\035" "AUID=\"alice\" UID=\"alice\" GID=\"alice\"";

inline constexpr std::string_view kDaemonStart =
    "type=DAEMON_START msg=audit(1700000000.442:1000): op=start ver=4.1.4 "
    "format=enriched kernel=0.0.0-generic auid=4294967295 pid=1575 uid=0 "
    "ses=4294967295 subj=unconfined  res=success"
    "\035" "AUID=\"unset\" UID=\"root\"";

} // namespace fixtures
