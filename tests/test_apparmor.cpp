#include <catch2/catch_all.hpp>

#include "AppArmorParser.h"

using namespace apparmor;

namespace {
const Rule* findFile(const Profile& p, const std::string& path,
                     Decision decision = Decision::Allow) {
    for (const auto& r : p.rules)
        if (r.kind == RuleKind::File && r.target == path &&
            r.decision == decision)
            return &r;
    return nullptr;
}
} // namespace

TEST_CASE("parseText reads a basic profile with attachment and rules") {
    const std::string text = R"(
abi <abi/3.0>,
include <tunables/global>
profile ping /{usr/,}bin/{,iputils-}ping {
  include <abstractions/base>
  include <abstractions/nameservice>

  capability net_raw,
  network inet raw,

  /{,usr/}bin/{,iputils-}ping mixr,
  /etc/modules.conf r,

  include if exists <local/bin.ping>
}
)";
    auto profiles = parseText(text, "bin.ping");
    REQUIRE(profiles.size() == 1);
    const Profile& p = profiles[0];

    CHECK(p.name == "ping");
    CHECK(p.attachment == "/{usr/,}bin/{,iputils-}ping");
    CHECK(p.sourceFile == "bin.ping");
    CHECK_FALSE(p.complain());

    // Profile-level includes are captured; global/tunable ones are not.
    CHECK(p.includes.size() == 3);
    CHECK(p.includes[0] == "abstractions/base");
    CHECK(p.includes[2] == "local/bin.ping");

    const Rule* ping = findFile(p, "/{,usr/}bin/{,iputils-}ping");
    REQUIRE(ping != nullptr);
    CHECK(ping->perms == "mixr");

    bool hasCap = false, hasNet = false;
    for (const auto& r : p.rules) {
        if (r.kind == RuleKind::Capability && r.target == "net_raw")
            hasCap = true;
        if (r.kind == RuleKind::Network && r.target == "inet raw")
            hasNet = true;
    }
    CHECK(hasCap);
    CHECK(hasNet);
}

TEST_CASE("deny rules are classified as taken access, not given") {
    const std::string text = R"(
profile lsb_release {
  owner @{PROC}/@{pid}/fd/ r,
  /usr/bin/lsb_release r,
  deny /usr/bin/apt-cache x,
  deny /tmp/gtalkplugin.log w,
}
)";
    auto profiles = parseText(text, "lsb_release");
    REQUIRE(profiles.size() == 1);
    const Profile& p = profiles[0];

    CHECK(p.denyCount() == 2);
    CHECK(p.allowCount() == 2);

    const Rule* deny = findFile(p, "/usr/bin/apt-cache", Decision::Deny);
    REQUIRE(deny != nullptr);
    CHECK(deny->perms == "x");
    CHECK(deny->decision == Decision::Deny);

    // The "owner" qualifier is recorded and does not swallow the path.
    const Rule* fd = findFile(p, "@{PROC}/@{pid}/fd/");
    REQUIRE(fd != nullptr);
    CHECK(fd->owner);
    CHECK(fd->perms == "r");
}

TEST_CASE("flags=(complain) marks a profile as log-only") {
    auto profiles = parseText("profile demo /usr/bin/demo flags=(complain) {\n"
                              "  /etc/demo.conf r,\n"
                              "}\n");
    REQUIRE(profiles.size() == 1);
    CHECK(profiles[0].complain());
    CHECK(profiles[0].attachment == "/usr/bin/demo");
}

TEST_CASE("nested child profiles are parsed as children") {
    const std::string text = R"(
profile dnsmasq /usr/{bin,sbin}/dnsmasq flags=(attach_disconnected) {
  /usr/{bin,sbin}/dnsmasq mr,
  /usr/lib/libvirt/libvirt_leaseshelper Cx -> libvirt_leaseshelper,

  profile libvirt_leaseshelper {
    /etc/libnl-3/classid r,
    @{run}/leaseshelper.pid rwk,
  }
}
)";
    auto profiles = parseText(text, "usr.sbin.dnsmasq");
    REQUIRE(profiles.size() == 1);
    const Profile& parent = profiles[0];

    CHECK(parent.name == "dnsmasq");
    REQUIRE(parent.children.size() == 1);

    const Profile& child = parent.children[0];
    CHECK(child.name == "libvirt_leaseshelper");
    CHECK(child.sourceFile == "usr.sbin.dnsmasq");
    const Rule* lock = findFile(child, "@{run}/leaseshelper.pid");
    REQUIRE(lock != nullptr);
    CHECK(lock->perms == "rwk");

    // The parent's exec transition keeps its path and perms separate.
    const Rule* exec = findFile(parent, "/usr/lib/libvirt/libvirt_leaseshelper");
    REQUIRE(exec != nullptr);
    CHECK(exec->perms == "Cx");
}

TEST_CASE("comments are stripped but #include directives survive") {
    const std::string text = R"(
profile demo {
  # this is a comment, ignore it
  /etc/demo.conf r, # trailing comment
  #include <abstractions/base>
}
)";
    auto profiles = parseText(text);
    REQUIRE(profiles.size() == 1);
    const Profile& p = profiles[0];
    REQUIRE(p.rules.size() == 1);
    CHECK(p.rules[0].target == "/etc/demo.conf");
    REQUIRE(p.includes.size() == 1);
    CHECK(p.includes[0] == "abstractions/base");
}

TEST_CASE("describePerms expands permission letters") {
    CHECK(describePerms("r") == "read");
    CHECK(describePerms("rw") == "read, write");
    CHECK(describePerms("mixr") == "mmap-exec, inherit-exec, read");
    CHECK(describePerms("") == "");
}
