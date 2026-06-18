#include <catch2/catch_all.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>

#include "AppArmorDenials.h"
#include "AppArmorEditor.h"
#include "AppArmorParser.h"

using namespace apparmor;

namespace {
Denial fileDenial(const char* profile, const char* target, const char* mask) {
    Denial d;
    d.profile = profile;
    d.operation = "open";
    d.klass = "file";
    d.target = target;
    d.deniedMask = mask;
    return d;
}

std::filesystem::path writeTemp(const std::string& name,
                                const std::string& content) {
    auto dir = std::filesystem::temp_directory_path() /
               ("aaedit_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    auto path = dir / name;
    std::ofstream(path) << content;
    return path;
}

std::string slurp(const std::filesystem::path& p) {
    std::ifstream in(p);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}
} // namespace

TEST_CASE("buildRule renders allow and deny rules per class") {
    CHECK(*buildRule(fileDenial("p", "/etc/foo", "r"), Decision::Allow) ==
          "/etc/foo r,");
    CHECK(*buildRule(fileDenial("p", "/etc/foo", "wr"), Decision::Deny) ==
          "deny /etc/foo wr,");

    Denial ptrace;
    ptrace.operation = "ptrace";
    ptrace.klass = "ptrace";
    ptrace.target = "/usr/bin/peer";
    ptrace.deniedMask = "readby";
    CHECK(*buildRule(ptrace, Decision::Allow) ==
          "ptrace (readby) peer=/usr/bin/peer,");
    CHECK(*buildRule(ptrace, Decision::Deny) ==
          "deny ptrace (readby) peer=/usr/bin/peer,");

    Denial sig;
    sig.operation = "signal";
    sig.klass = "signal";
    sig.target = "unconfined"; // the special keyword is not quoted
    sig.deniedMask = "receive";
    CHECK(*buildRule(sig, Decision::Allow) == "signal (receive) peer=unconfined,");

    Denial dbus;
    dbus.klass = "dbus";
    CHECK_FALSE(buildRule(dbus, Decision::Allow).has_value());
}

TEST_CASE("buildRule emits an owner rule when the access is owner-conditional") {
    Denial d = fileDenial("p", "/home/sigsegv/.config/x", "rc");
    d.owner = true;
    // owner sits after the (absent/deny) decision qualifier, before the path.
    CHECK(*buildRule(d, Decision::Allow) ==
          "owner /home/sigsegv/.config/x rw,");
    CHECK(*buildRule(d, Decision::Deny) ==
          "deny owner /home/sigsegv/.config/x rw,");
    d.owner = false;
    CHECK(*buildRule(d, Decision::Allow) == "/home/sigsegv/.config/x rw,");
}

TEST_CASE("ptrace peer with a glob profile name is escaped, not wildcarded") {
    // The peer is a profile NAME containing a literal '*' (from its attachment
    // glob). It must be escaped (\*) so the kernel matches that literal '*';
    // an unescaped '*' is a wildcard the kernel will not match against it.
    Denial d;
    d.operation = "ptrace";
    d.klass = "ptrace";
    d.profile = "/home/*/.local/share/app/jspawnhelper";
    d.target = "/home/*/.local/share/app/rustrover";
    d.deniedMask = "readby";
    CHECK(*buildRule(d, Decision::Allow) ==
          R"(ptrace (readby) peer=/home/\*/.local/share/app/rustrover,)");
    // The complementary peer rule escapes our own (globbed) profile name too.
    CHECK(*buildPeerRule(d, Decision::Allow) ==
          R"(ptrace (read) peer=/home/\*/.local/share/app/jspawnhelper,)");
}

TEST_CASE("buildPeerRule builds the complementary rule for the peer profile") {
    Denial d;
    d.operation = "ptrace";
    d.klass = "ptrace";
    d.profile = "/usr/bin/jspawnhelper";              // our profile
    d.target = "/usr/bin/rustrover";                  // the peer
    d.deniedMask = "readby";

    // The peer profile needs the inverse mode (readby -> read) with peer = us.
    CHECK(*buildPeerRule(d, Decision::Allow) ==
          "ptrace (read) peer=/usr/bin/jspawnhelper,");
    CHECK(*buildPeerRule(d, Decision::Deny) ==
          "deny ptrace (read) peer=/usr/bin/jspawnhelper,");

    // The other ptrace directions and signals invert too.
    d.deniedMask = "tracedby";
    CHECK(*buildPeerRule(d, Decision::Allow) ==
          "ptrace (trace) peer=/usr/bin/jspawnhelper,");

    Denial sig;
    sig.operation = "signal";
    sig.klass = "signal";
    sig.profile = "/usr/bin/a";
    sig.target = "/usr/bin/b";
    sig.deniedMask = "receive";
    CHECK(*buildPeerRule(sig, Decision::Allow) ==
          "signal (send) peer=/usr/bin/a,");

    // No peer rule for unconfined peers or non-peer-mediated classes.
    Denial unconf = d;
    unconf.target = "unconfined";
    CHECK_FALSE(buildPeerRule(unconf, Decision::Allow).has_value());
    Denial file;
    file.klass = "file";
    file.profile = "/p";
    file.target = "/etc/x";
    file.deniedMask = "r";
    CHECK_FALSE(buildPeerRule(file, Decision::Allow).has_value());
}

TEST_CASE("setOwnerQualifier adds/removes owner, preserving qualifier order") {
    // Add owner.
    CHECK(setOwnerQualifier("/home/u/x rw,", true) == "owner /home/u/x rw,");
    CHECK(setOwnerQualifier("deny /home/u/x rw,", true) ==
          "deny owner /home/u/x rw,");
    CHECK(setOwnerQualifier("audit deny /x r,", true) ==
          "audit deny owner /x r,");
    // Remove owner.
    CHECK(setOwnerQualifier("owner /home/u/x rw,", false) == "/home/u/x rw,");
    CHECK(setOwnerQualifier("deny owner /x r,", false) == "deny /x r,");
    // Idempotent: adding when present / removing when absent is a no-op.
    CHECK(setOwnerQualifier("owner /x r,", true) == "owner /x r,");
    CHECK(setOwnerQualifier("/x r,", false) == "/x r,");
    // The path/perms (the body) are left untouched, including embedded spaces.
    CHECK(setOwnerQualifier("\"/home/u/a b\" rw,", true) ==
          "owner \"/home/u/a b\" rw,");
}

TEST_CASE("ruleSupportsOwner is true only for file rules") {
    CHECK(ruleSupportsOwner("/etc/x r,"));
    CHECK(ruleSupportsOwner("owner /home/u/x rw,"));
    CHECK_FALSE(ruleSupportsOwner("signal (receive) peer=unconfined,"));
    CHECK_FALSE(ruleSupportsOwner("capability net_raw,"));
}

TEST_CASE("buildRule maps audit-mask create/delete letters to valid perms") {
    // 'c' (create) and 'd' (delete) are not rule permissions; they map to 'w'.
    CHECK(*buildRule(fileDenial("p", "/dev/shm/R*", "c"), Decision::Allow) ==
          "/dev/shm/R* w,");
    CHECK(*buildRule(fileDenial("p", "/tmp/x", "d"), Decision::Allow) ==
          "/tmp/x w,");
    CHECK(*buildRule(fileDenial("p", "/tmp/x", "rc"), Decision::Allow) ==
          "/tmp/x rw,");
    // 'w' already covers append, and duplicates collapse.
    CHECK(*buildRule(fileDenial("p", "/tmp/x", "wc"), Decision::Allow) ==
          "/tmp/x w,");

    CHECK(normalizeFilePerms("c") == "w");
    CHECK(normalizeFilePerms("wr") == "wr"); // order preserved
    CHECK(normalizeFilePerms("rwcd") == "rw");
}

TEST_CASE("addRuleToProfile inserts the rule inside the profile body") {
    const std::string before =
        "profile demo /usr/bin/demo {\n"
        "  /etc/a r,\n"
        "  include if exists <local/demo>\n"
        "}\n";
    auto path = writeTemp("demo", before);

    auto res = addRuleToProfile(path.string(), "demo", "/etc/secret rw,");
    CHECK(res.ok);

    const std::string after = slurp(path);
    // The new rule is present, inside the block, and the old rule survives.
    CHECK(after.find("/etc/secret rw,") != std::string::npos);
    CHECK(after.find("/etc/a r,") != std::string::npos);
    CHECK(after.find("/etc/secret") < after.rfind('}'));

    auto profiles = parseText(after, "demo");
    REQUIRE(profiles.size() == 1);
    CHECK(profiles[0].rules.size() == 2);

    std::filesystem::remove_all(path.parent_path());
}

TEST_CASE("addRuleToProfile subsumes covered rules: trims perms, deletes empties") {
    const std::string before =
        "profile demo /usr/bin/demo {\n"
        "  /etc/keep r,\n"                  // not covered by /var/** -> untouched
        "  /var/log/app.log r,\n"           // fully covered (r) -> deleted
        "  /var/lib/app/db rwk,\n"          // partially covered (rw) -> becomes k
        "  deny /var/secret w,\n"           // different decision -> untouched
        "  /var/glob/* rw,\n"               // glob target -> untouched (not concrete)
        "}\n";
    auto path = writeTemp("demo_sub", before);

    auto res = addRuleToProfile(path.string(), "demo", "/var/** rw,");
    CHECK(res.ok);

    const std::string after = slurp(path);
    auto profiles = parseText(after, "demo");
    REQUIRE(profiles.size() == 1);
    const auto& rules = profiles[0].rules;

    auto find = [&](const std::string& target) -> const apparmor::Rule* {
        for (const auto& r : rules)
            if (r.target == target)
                return &r;
        return nullptr;
    };

    // Unrelated and non-concrete and cross-decision rules are preserved.
    CHECK(find("/etc/keep") != nullptr);
    CHECK(find("/var/glob/*") != nullptr);
    const apparmor::Rule* secret = nullptr;
    for (const auto& r : rules)
        if (r.target == "/var/secret" && r.decision == Decision::Deny)
            secret = &r;
    CHECK(secret != nullptr);

    // Fully-covered rule removed; partially-covered rule keeps only "k".
    CHECK(find("/var/log/app.log") == nullptr);
    REQUIRE(find("/var/lib/app/db") != nullptr);
    CHECK(find("/var/lib/app/db")->perms == "k");

    // The new rule is present.
    REQUIRE(find("/var/**") != nullptr);
    CHECK(find("/var/**")->perms == "rw");

    std::filesystem::remove_all(path.parent_path());
}

TEST_CASE("addRuleToProfile only subsumes same owner/audit qualifier") {
    const std::string before =
        "profile demo {\n"
        "  owner /data/x r,\n"   // owner-conditional -> not covered by plain rule
        "  /data/y r,\n"         // plain -> covered and removed
        "}\n";
    auto path = writeTemp("demo_qual", before);

    auto res = addRuleToProfile(path.string(), "demo", "/data/** r,");
    CHECK(res.ok);
    const std::string after = slurp(path);
    CHECK(after.find("owner /data/x r,") != std::string::npos); // kept
    CHECK(after.find("/data/y r,") == std::string::npos);       // removed

    std::filesystem::remove_all(path.parent_path());
}

TEST_CASE("reverseDenyRule turns a deny rule into an allow in place") {
    const std::string before =
        "profile demo /usr/bin/demo {\n"
        "  /etc/a r,\n"
        "  deny /usr/bin/apt-cache x,\n"
        "  audit deny /tmp/log w,\n"
        "}\n";
    auto path = writeTemp("demo3", before);

    auto res = reverseDenyRule(path.string(), "demo", "deny /usr/bin/apt-cache x");
    CHECK(res.ok);

    const std::string after = slurp(path);
    // The deny became a plain allow; the other rules are untouched.
    CHECK(after.find("/usr/bin/apt-cache x,") != std::string::npos);
    CHECK(after.find("deny /usr/bin/apt-cache") == std::string::npos);
    CHECK(after.find("audit deny /tmp/log w,") != std::string::npos);

    auto profiles = parseText(after, "demo");
    REQUIRE(profiles.size() == 1);
    CHECK(profiles[0].rules.size() == 3); // count unchanged
    std::size_t denies = 0;
    for (const auto& r : profiles[0].rules)
        if (r.decision == Decision::Deny)
            ++denies;
    CHECK(denies == 1); // one fewer deny than before

    // "audit deny" keeps the audit qualifier when reversed.
    auto res2 = reverseDenyRule(path.string(), "demo", "audit deny /tmp/log w");
    CHECK(res2.ok);
    const std::string after2 = slurp(path);
    CHECK(after2.find("audit /tmp/log w,") != std::string::npos);
    CHECK(after2.find("deny /tmp/log") == std::string::npos);

    std::filesystem::remove_all(path.parent_path());
}

TEST_CASE("reverseDenyRule leaves the file untouched when the rule is gone") {
    const std::string before = "profile demo {\n  /etc/a r,\n}\n";
    auto path = writeTemp("demo4", before);

    auto res = reverseDenyRule(path.string(), "demo", "deny /etc/secret w");
    CHECK_FALSE(res.ok);
    CHECK(slurp(path) == before); // byte-for-byte unchanged

    std::filesystem::remove_all(path.parent_path());
}

TEST_CASE("reloadProfile is gated on root and refuses cleanly otherwise") {
    // The test suite does not run as root, so reapplying must refuse without
    // attempting to spawn apparmor_parser.
    if (!canReloadProfiles()) {
        auto rr = reloadProfile("/etc/apparmor.d/does-not-matter");
        CHECK_FALSE(rr.ok);
        CHECK(rr.message.find("root") != std::string::npos);
    }
}

TEST_CASE("addRuleToProfile leaves the file untouched on error") {
    const std::string before = "profile demo {\n  /etc/a r,\n}\n";
    auto path = writeTemp("demo2", before);

    auto res = addRuleToProfile(path.string(), "nonexistent", "/etc/x r,");
    CHECK_FALSE(res.ok);
    CHECK(slurp(path) == before); // byte-for-byte unchanged

    // No stray temp files left behind in the directory.
    int leftovers = 0;
    for (auto& e : std::filesystem::directory_iterator(path.parent_path()))
        if (e.path().filename().string().find(".aatmp") != std::string::npos)
            ++leftovers;
    CHECK(leftovers == 0);

    std::filesystem::remove_all(path.parent_path());
}
