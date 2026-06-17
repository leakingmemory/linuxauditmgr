#include <catch2/catch_all.hpp>

#include <regex>

#include "AuditParser.h"
#include "fixtures.h"

using namespace audit;

namespace {
Record parse(std::string_view line) {
    auto r = parseLine(line);
    REQUIRE(r.has_value());
    return std::move(*r);
}
} // namespace

TEST_CASE("decodeHexField decodes hex and turns NUL into spaces") {
    CHECK(decodeHexField("2F62696E2F7073") == "/bin/ps");
    // NUL bytes (00) separate argv entries and become spaces.
    CHECK(decodeHexField("2F62696E2F7073002D65") == "/bin/ps -e");
    CHECK(decodeHexField(fixtures::kProctitle.substr(
              fixtures::kProctitle.find("proctitle=") + 10)) ==
          "/bin/ps -e --format %P%p%a");
}

TEST_CASE("decodeHexField passes non-hex through unchanged") {
    CHECK(decodeHexField("hello world") == "hello world");
    CHECK(decodeHexField("ABC") == "ABC");      // odd length -> not hex
    CHECK(decodeHexField("") == "");
    CHECK(decodeHexField("(none)") == "(none)");
}

TEST_CASE("parseLine rejects non-records") {
    CHECK_FALSE(parseLine("").has_value());
    CHECK_FALSE(parseLine("   ").has_value());
    CHECK_FALSE(parseLine("not an audit line").has_value());
    CHECK_FALSE(parseLine("type=AVC without msg").has_value());
}

TEST_CASE("parseLine extracts type, serial, timestamp and fields") {
    Record r = parse(fixtures::kAvc);
    CHECK(r.type == "AVC");
    CHECK(r.serial == 1001);
    CHECK(r.timestamp == Catch::Approx(1700000001.123));
    CHECK(r.get("apparmor") == "DENIED");
    CHECK(r.get("operation") == "ptrace");
    CHECK(r.get("profile") == "/opt/app/bin/launcher");
    CHECK(r.get("peer") == "/opt/app/bin/peer");
    CHECK(r.get("pid") == "4242");
    CHECK_FALSE(r.get("nonexistent").has_value());
}

TEST_CASE("ENRICHED resolved fields are parsed and preferred by getResolved") {
    Record r = parse(fixtures::kSyscall);
    // Raw values still available via get().
    CHECK(r.get("syscall") == "0");
    CHECK(r.get("uid") == "1000");
    // Resolved (post-0x1d) values overlay them.
    CHECK(r.getResolved("syscall") == "read");
    CHECK(r.getResolved("uid") == "alice");
    CHECK(r.getResolved("auid") == "alice");
    CHECK(r.getResolved("arch") == "x86_64");
    // getResolved falls back to the raw value when no resolved one exists.
    CHECK(r.getResolved("exit") == "205");
}

TEST_CASE("SYSCALL register args are NOT hex-decoded") {
    Record r = parse(fixtures::kSyscall);
    // a1 is a raw pointer value; it must survive verbatim, not be "decoded".
    CHECK(r.get("a1") == "7ffcaabbccdd");
    CHECK(r.get("a0") == "5");
}

TEST_CASE("EXECVE quoted argv is preserved") {
    Record r = parse(fixtures::kExecve);
    CHECK(r.type == "EXECVE");
    CHECK(r.get("argc") == "3");
    CHECK(r.get("a0") == "/opt/app/bin/launcher");
    CHECK(r.get("a1") == "21.0.8+9-b1092.38");
    CHECK(r.get("a2") == "211:214:218");
}

TEST_CASE("hex-encoded proctitle and exe are decoded during parsing") {
    CHECK(parse(fixtures::kProctitle).get("proctitle") ==
          "/bin/ps -e --format %P%p%a");
    CHECK(parse(fixtures::kAnomAbend).get("exe") ==
          "/usr/bin/gnome-shell (deleted)");
}

TEST_CASE("glued res=1<GS>UID form (LOGIN) splits raw and resolved") {
    Record r = parse(fixtures::kLogin);
    CHECK(r.type == "LOGIN");
    CHECK(r.get("res") == "1");
    CHECK(r.get("auid") == "32");
    CHECK(r.getResolved("auid") == "gdm");
    CHECK(r.getResolved("uid") == "root");
}

TEST_CASE("quoted values may contain spaces") {
    Record r = parse(R"(type=USER_CMD msg=audit(1700000005.000:1005): cmd="ls -la /tmp" res=success)");
    CHECK(r.get("cmd") == "ls -la /tmp");
    CHECK(r.get("res") == "success");
}

TEST_CASE("syscallName maps known x86_64 numbers") {
    CHECK(syscallName("c000003e", "0") == "read");
    CHECK(syscallName("c000003e", "59") == "execve");
    CHECK(syscallName("c000003e", "101") == "ptrace");
    CHECK(syscallName("c000003e", "99999").empty());
}

// ---- EventGrouper --------------------------------------------------------

TEST_CASE("EventGrouper groups records by (serial,timestamp)") {
    EventGrouper g;
    CHECK_FALSE(g.add(parse(fixtures::kAvc)).has_value());       // 1001
    CHECK_FALSE(g.add(parse(fixtures::kSyscall)).has_value());   // 1001
    CHECK_FALSE(g.add(parse(fixtures::kProctitle)).has_value()); // 1001

    // The EXECVE belongs to a new event (1002), so adding it completes 1001.
    auto completed = g.add(parse(fixtures::kExecve));
    REQUIRE(completed.has_value());
    CHECK(completed->serial == 1001);
    CHECK(completed->records.size() == 3);

    // The final pending event is emitted by flush().
    auto last = g.flush();
    REQUIRE(last.has_value());
    CHECK(last->serial == 1002);
    CHECK(last->records.size() == 1);

    CHECK_FALSE(g.flush().has_value()); // nothing left
}

// ---- Event accessors -----------------------------------------------------

namespace {
Event buildAvcEvent() {
    EventGrouper g;
    g.add(parse(fixtures::kAvc));
    g.add(parse(fixtures::kSyscall));
    g.add(parse(fixtures::kProctitle));
    auto ev = g.flush();
    REQUIRE(ev.has_value());
    return std::move(*ev);
}
} // namespace

TEST_CASE("Event aggregates types, pid, comm, exe across records") {
    Event ev = buildAvcEvent();
    CHECK(ev.typesJoined() == "AVC,SYSCALL,PROCTITLE");
    CHECK(ev.pid() == "4242");
    CHECK(ev.comm() == "worker");
    CHECK(ev.exe() == "/opt/app/bin/worker");
}

TEST_CASE("Event summary describes AVC denials and SYSCALLs") {
    std::string s = buildAvcEvent().summary();
    CHECK(s.find("DENIED") != std::string::npos);
    CHECK(s.find("ptrace") != std::string::npos);
    CHECK(s.find("/opt/app/bin/launcher") != std::string::npos);

    // A SYSCALL-only event summarises with the resolved syscall name.
    EventGrouper g;
    g.add(parse(fixtures::kSyscall));
    Event sc = *g.flush();
    CHECK(sc.summary().find("read") != std::string::npos);
}

TEST_CASE("Event formattedTime has the expected shape") {
    // Exact value is timezone-dependent; assert the format only.
    std::string t = buildAvcEvent().formattedTime();
    std::regex re(R"(^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$)");
    CHECK(std::regex_match(t, re));
}

TEST_CASE("Event detail includes resolved values and decoded proctitle") {
    std::string d = buildAvcEvent().detail();
    CHECK(d.find("-- resolved --") != std::string::npos);
    CHECK(d.find("syscall = read") != std::string::npos);
    CHECK(d.find("/bin/ps -e --format") != std::string::npos);
}
