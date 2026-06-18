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

TEST_CASE("allowFromEvent extracts ALLOWED records, not DENIED ones") {
    const std::string allowed =
        R"(type=AVC msg=audit(1.0:1): apparmor="ALLOWED" operation="open" )"
        R"(class="file" profile="/usr/bin/app" name="/etc/app.conf" pid=42 )"
        R"(comm="app" requested_mask="r" denied_mask="r")";

    auto a = allowFromEvent(eventFromLine(allowed));
    REQUIRE(a.has_value());
    CHECK(a->profile == "/usr/bin/app");
    CHECK(a->target == "/etc/app.conf");
    CHECK(a->requestedMask == "r");
    CHECK_FALSE(denialFromEvent(eventFromLine(allowed)).has_value());

    const std::string denied =
        R"(type=AVC msg=audit(1.0:2): apparmor="DENIED" operation="open" profile="p")";
    CHECK_FALSE(allowFromEvent(eventFromLine(denied)).has_value());
}

TEST_CASE("denialFromEvent sets owner when fsuid == ouid") {
    // mknod on a file the task owns: fsuid == ouid -> an owner rule applies.
    const std::string owned =
        R"(type=AVC msg=audit(1.0:1): apparmor="DENIED" operation="mknod" )"
        R"(class="file" profile="/usr/bin/app" name="/home/u/.config/x" )"
        R"(pid=42 comm="app" requested_mask="c" denied_mask="c" )"
        R"(fsuid=1000 ouid=1000)";
    auto a = denialFromEvent(eventFromLine(owned));
    REQUIRE(a.has_value());
    CHECK(a->owner);

    // Accessing a file owned by someone else (fsuid != ouid): not owner.
    const std::string other =
        R"(type=AVC msg=audit(1.0:2): apparmor="DENIED" operation="open" )"
        R"(class="file" profile="/usr/bin/app" name="/etc/shadow" pid=42 )"
        R"(comm="app" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0)";
    auto b = denialFromEvent(eventFromLine(other));
    REQUIRE(b.has_value());
    CHECK_FALSE(b->owner);

    // No uid info at all: default to a non-owner rule.
    const std::string none =
        R"(type=AVC msg=audit(1.0:3): apparmor="DENIED" operation="open" )"
        R"(class="file" profile="/usr/bin/app" name="/tmp/x" pid=42 )"
        R"(comm="app" requested_mask="r" denied_mask="r")";
    auto c = denialFromEvent(eventFromLine(none));
    REQUIRE(c.has_value());
    CHECK_FALSE(c->owner);
}

TEST_CASE("correlateAllows distinguishes by-rule, complain-only and unknown") {
    auto profiles = parseText(R"(
profile enforced /usr/bin/enforced {
  /etc/allowed r,
}
profile lax /usr/bin/lax flags=(complain) {
  /etc/known r,
}
)",
                              "p");

    auto mk = [](const char* prof, const char* target, const char* mask) {
        DenialGroup g;
        g.sample.profile = prof;
        g.sample.operation = "open";
        g.sample.klass = "file";
        g.sample.target = target;
        g.sample.requestedMask = mask;
        g.count = 1;
        return g;
    };

    std::vector<DenialGroup> groups = {
        mk("/usr/bin/enforced", "/etc/allowed", "r"),  // matching allow rule
        mk("/usr/bin/lax", "/etc/known", "r"),         // matched -> by rule
        mk("/usr/bin/lax", "/etc/other", "r"),         // complain, no rule
        mk("/usr/bin/enforced", "/etc/x", "r"),        // enforce, no rule -> abstraction
        mk("/usr/bin/missing", "/x", "r"),             // profile not loaded
    };
    correlateAllows(groups, profiles);

    CHECK(groups[0].correlation == Correlation::AllowedByRule);
    CHECK(groups[0].matchedRule == "/etc/allowed r");
    CHECK(groups[1].correlation == Correlation::AllowedByRule);
    CHECK(groups[2].correlation == Correlation::ComplainOnly);
    CHECK(groups[3].correlation == Correlation::AllowedByRule); // via abstraction
    CHECK(groups[3].matchedRule.empty());
    CHECK(groups[4].correlation == Correlation::Unknown);
}

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

TEST_CASE("correlation is owner-aware: owner rules don't cover non-owner access") {
    auto profiles = parseText(R"(
profile app /usr/bin/app {
  owner /data/** rw,
  deny owner /secret/** rw,
}
)",
                              "app");

    auto mkGroup = [](const char* target, const char* mask, bool owner) {
        DenialGroup g;
        g.sample.profile = "/usr/bin/app";
        g.sample.operation = "open";
        g.sample.klass = "file";
        g.sample.target = target;
        g.sample.requestedMask = mask;
        g.sample.deniedMask = mask;
        g.sample.owner = owner;
        g.count = 1;
        return g;
    };

    SECTION("owner allow rule covers an owner access but not a non-owner one") {
        std::vector<DenialGroup> groups = {
            mkGroup("/data/x", "r", /*owner=*/true),   // owner -> covered
            mkGroup("/data/x", "r", /*owner=*/false),  // non-owner -> not covered
        };
        correlateAllows(groups, profiles);
        CHECK(groups[0].correlation == Correlation::AllowedByRule);
        // A non-owner access an owner rule cannot satisfy falls through to the
        // enforcing "must be via an abstraction" branch, never the owner rule.
        CHECK(groups[0].matchedRule == "owner /data/** rw");
        CHECK(groups[1].matchedRule.empty());
    }

    SECTION("owner deny rule only fires for an owner access") {
        std::vector<DenialGroup> groups = {
            mkGroup("/secret/k", "r", /*owner=*/true),   // owner -> explicit deny
            mkGroup("/secret/k", "r", /*owner=*/false),  // non-owner -> implicit
        };
        correlate(groups, profiles);
        CHECK(groups[0].correlation == Correlation::ExplicitDeny);
        CHECK(groups[0].matchedRule == "deny owner /secret/** rw");
        CHECK(groups[1].correlation == Correlation::Implicit);
    }

    SECTION("a plain rule covers both owner and non-owner access") {
        auto plain = parseText(R"(
profile app /usr/bin/app {
  /data/** rw,
}
)",
                               "app");
        std::vector<DenialGroup> groups = {
            mkGroup("/data/x", "r", /*owner=*/true),
            mkGroup("/data/x", "r", /*owner=*/false),
        };
        correlateAllows(groups, plain);
        CHECK(groups[0].matchedRule == "/data/** rw");
        CHECK(groups[1].matchedRule == "/data/** rw");
    }
}
