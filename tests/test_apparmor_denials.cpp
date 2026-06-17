#include <catch2/catch_all.hpp>

#include "AppArmorDenials.h"
#include "AppArmorParser.h"
#include "AuditParser.h"

using namespace apparmor;

namespace {
audit::Event eventFromLine(const std::string& line) {
    audit::Event ev;
    auto rec = audit::parseLine(line);
    REQUIRE(rec.has_value());
    ev.timestamp = rec->timestamp;
    ev.serial = rec->serial;
    ev.records.push_back(std::move(*rec));
    return ev;
}
} // namespace

TEST_CASE("globMatch handles stars, double-stars and braces") {
    CHECK(globMatch("/usr/bin/foo", "/usr/bin/foo"));
    CHECK_FALSE(globMatch("/usr/bin/foo", "/usr/bin/bar"));

    // '*' matches within a path segment but not across '/'.
    CHECK(globMatch("/usr/*/foo", "/usr/bin/foo"));
    CHECK_FALSE(globMatch("/usr/*/foo", "/usr/local/bin/foo"));

    // '**' crosses '/'.
    CHECK(globMatch("/usr/**", "/usr/a/b/c"));
    CHECK(globMatch("/home/*/.local/**", "/home/sigsegv/.local/share/x"));

    // Brace alternation, including the empty-alternative idiom.
    CHECK(globMatch("/{usr/,}bin/ping", "/usr/bin/ping"));
    CHECK(globMatch("/{usr/,}bin/ping", "/bin/ping"));
    CHECK(globMatch("/usr/lib{,64}/x", "/usr/lib64/x"));
    CHECK(globMatch("/usr/lib{,64}/x", "/usr/lib/x"));
    CHECK_FALSE(globMatch("/usr/lib{,64}/x", "/usr/lib32/x"));
}

TEST_CASE("denialFromEvent extracts AppArmor DENIED fields") {
    const std::string line =
        R"(type=AVC msg=audit(1781438984.083:229713): apparmor="DENIED" )"
        R"(operation="open" class="file" profile="/usr/lib64/thunderbird/glxtest" )"
        R"(name="/sys/devices/system/cpu/cpu3/cpu_capacity" pid=3150201 )"
        R"(comm="glxtest" requested_mask="r" denied_mask="r")";

    auto d = denialFromEvent(eventFromLine(line));
    REQUIRE(d.has_value());
    CHECK(d->profile == "/usr/lib64/thunderbird/glxtest");
    CHECK(d->operation == "open");
    CHECK(d->klass == "file");
    CHECK(d->target == "/sys/devices/system/cpu/cpu3/cpu_capacity");
    CHECK(d->deniedMask == "r");
    CHECK(d->comm == "glxtest");
    CHECK(d->pid == "3150201");
}

TEST_CASE("denialFromEvent ignores non-denials") {
    // An ALLOWED apparmor record is not a denial.
    auto allowed = denialFromEvent(eventFromLine(
        R"(type=AVC msg=audit(1.0:1): apparmor="ALLOWED" operation="open" profile="p")"));
    CHECK_FALSE(allowed.has_value());

    // A plain SYSCALL record is not an AppArmor event at all.
    auto syscall = denialFromEvent(eventFromLine(
        R"(type=SYSCALL msg=audit(1.0:2): arch=c000003e syscall=2 success=no)"));
    CHECK_FALSE(syscall.has_value());
}

TEST_CASE("aggregateDenials collapses identical denials and counts them") {
    auto mk = [](const char* prof, const char* op, const char* target,
                 double ts) {
        Denial d;
        d.profile = prof;
        d.operation = op;
        d.target = target;
        d.deniedMask = "r";
        d.timestamp = ts;
        return d;
    };
    std::vector<Denial> denials = {
        mk("/a", "open", "/etc/x", 10),
        mk("/a", "open", "/etc/x", 30),
        mk("/a", "open", "/etc/x", 20),
        mk("/b", "ptrace", "/c", 5),
    };

    auto groups = aggregateDenials(denials);
    REQUIRE(groups.size() == 2);
    // Sorted by descending count: the /etc/x group (3) comes first.
    CHECK(groups[0].sample.profile == "/a");
    CHECK(groups[0].count == 3);
    CHECK(groups[0].firstSeen == 10);
    CHECK(groups[0].lastSeen == 30);
    CHECK(groups[1].count == 1);
}

TEST_CASE("correlate distinguishes explicit, implicit and unknown denials") {
    auto profiles = parseText(R"(
profile app /usr/bin/app {
  /etc/allowed r,
  deny /etc/secret/** rw,
}
)",
                              "app");

    auto mkGroup = [](const char* prof, const char* target, const char* mask) {
        DenialGroup g;
        g.sample.profile = prof;
        g.sample.operation = "open";
        g.sample.klass = "file";
        g.sample.target = target;
        g.sample.deniedMask = mask;
        g.count = 1;
        return g;
    };

    std::vector<DenialGroup> groups = {
        mkGroup("/usr/bin/app", "/etc/secret/key", "r"),  // explicit deny
        mkGroup("/usr/bin/app", "/etc/other", "r"),       // implicit
        mkGroup("/usr/bin/elsewhere", "/x", "r"),         // unknown profile
    };

    correlate(groups, profiles);

    CHECK(groups[0].correlation == Correlation::ExplicitDeny);
    CHECK(groups[0].matchedRule == "deny /etc/secret/** rw");
    CHECK(groups[1].correlation == Correlation::Implicit);
    CHECK(groups[2].correlation == Correlation::Unknown);
}
