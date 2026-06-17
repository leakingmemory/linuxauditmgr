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
          R"(ptrace (readby) peer="/usr/bin/peer",)");
    CHECK(*buildRule(ptrace, Decision::Deny) ==
          R"(deny ptrace (readby) peer="/usr/bin/peer",)");

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
