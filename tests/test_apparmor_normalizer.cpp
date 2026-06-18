#include <catch2/catch_all.hpp>

#include <set>

#include "AppArmorNormalizer.h"
#include "AppArmorParser.h"

using namespace apparmor;

TEST_CASE("normalize sorts, dedupes and merges rules; keeps preamble/header") {
    const std::string input =
        "# preamble comment\n"
        "profile demo /usr/bin/demo {\n"
        "  /etc/b r,\n"
        "  /etc/a r,\n"
        "  /etc/a w,\n"
        "  capability net_raw,\n"
        "  /etc/a r,\n"  // exact duplicate
        "}\n";

    auto res = normalizeProfileText(input);
    CHECK(res.changed);
    // Preamble and header survive verbatim.
    CHECK(res.normalized.find("# preamble comment\n") != std::string::npos);
    CHECK(res.normalized.find("profile demo /usr/bin/demo {") !=
          std::string::npos);

    auto profs = parseText(res.normalized);
    REQUIRE(profs.size() == 1);
    const auto& rules = profs[0].rules;
    REQUIRE(rules.size() == 3); // capability + merged /etc/a + /etc/b

    // capability comes first (kind order), then file rules sorted by path.
    CHECK(rules[0].kind == RuleKind::Capability);
    CHECK(rules[1].target == "/etc/a");
    CHECK(rules[1].perms == "rw"); // r and w merged, duplicate dropped
    CHECK(rules[2].target == "/etc/b");
}

TEST_CASE("normalization is idempotent") {
    const std::string input =
        "profile demo {\n"
        "  /etc/b r,\n"
        "  /etc/a w,\n"
        "  /etc/a r,\n"
        "}\n";
    auto once = normalizeProfileText(input);
    REQUIRE(once.changed);
    auto twice = normalizeProfileText(once.normalized);
    CHECK_FALSE(twice.changed); // already canonical
    CHECK(twice.normalized == once.normalized);
}

TEST_CASE("nested child profiles are preserved and normalized too") {
    const std::string input =
        "profile p /usr/bin/p {\n"
        "  /b r,\n"
        "  profile child {\n"
        "    /y r,\n"
        "    /x r,\n"
        "  }\n"
        "  /a r,\n"
        "}\n";

    auto res = normalizeProfileText(input);
    CHECK(res.changed);

    auto profs = parseText(res.normalized);
    REQUIRE(profs.size() == 1);
    REQUIRE(profs[0].rules.size() == 2);
    CHECK(profs[0].rules[0].target == "/a");
    CHECK(profs[0].rules[1].target == "/b");

    REQUIRE(profs[0].children.size() == 1);
    const auto& child = profs[0].children[0];
    CHECK(child.name == "child");
    REQUIRE(child.rules.size() == 2);
    CHECK(child.rules[0].target == "/x");
    CHECK(child.rules[1].target == "/y");
}

TEST_CASE("exec-transition rules are kept verbatim, not merged") {
    const std::string input =
        "profile p {\n"
        "  /usr/bin/tool Px -> tool,\n"
        "  /usr/bin/tool r,\n"
        "}\n";
    auto res = normalizeProfileText(input);

    // The Px rule must survive untouched (not merged into the r rule).
    CHECK(res.normalized.find("/usr/bin/tool Px -> tool,") != std::string::npos);
    auto profs = parseText(res.normalized);
    REQUIRE(profs.size() == 1);
    CHECK(profs[0].rules.size() == 2);
}

TEST_CASE("owner rules are grouped together after non-owner (aa-tools order)") {
    const std::string input =
        "profile p {\n"
        "  owner /a r,\n"
        "  /d r,\n"
        "  owner /c r,\n"
        "  /b r,\n"
        "}\n";
    auto res = normalizeProfileText(input);
    REQUIRE(res.changed);

    auto profs = parseText(res.normalized);
    REQUIRE(profs.size() == 1);
    const auto& rules = profs[0].rules;
    REQUIRE(rules.size() == 4);

    // Non-owner rules first (sorted), then the owner rules grouped (sorted).
    CHECK_FALSE(rules[0].owner);
    CHECK(rules[0].target == "/b");
    CHECK_FALSE(rules[1].owner);
    CHECK(rules[1].target == "/d");
    CHECK(rules[2].owner);
    CHECK(rules[2].target == "/a");
    CHECK(rules[3].owner);
    CHECK(rules[3].target == "/c");
}

TEST_CASE("deny rules are emitted before allow rules within a kind") {
    const std::string input =
        "profile p {\n"
        "  /allow r,\n"
        "  deny /blocked w,\n"
        "}\n";
    auto res = normalizeProfileText(input);
    auto profs = parseText(res.normalized);
    REQUIRE(profs.size() == 1);
    REQUIRE(profs[0].rules.size() == 2);
    CHECK(profs[0].rules[0].decision == Decision::Deny);
    CHECK(profs[0].rules[1].decision == Decision::Allow);
}

TEST_CASE("quoted paths with spaces are preserved verbatim, not corrupted") {
    const std::string input =
        "profile p {\n"
        "  deny owner \"/home/*/buglist.cgi\\?chfield=\\[Bug creation\\]\" r,\n"
        "  /etc/a r,\n"
        "}\n";
    auto res = normalizeProfileText(input);
    // The exact quoted rule must survive unchanged.
    CHECK(res.normalized.find(
              "deny owner \"/home/*/buglist.cgi\\?chfield=\\[Bug creation\\]\" "
              "r,") != std::string::npos);
    // And re-parsing keeps both rules intact.
    auto profs = parseText(res.normalized);
    REQUIRE(profs.size() == 1);
    CHECK(profs[0].rules.size() == 2);
}

TEST_CASE("an unquoted path with a '#' in it is not treated as a comment") {
    // '#' embedded in a path (e.g. KDE/Qt temp files) is part of the path; only
    // a '#' at line start or after whitespace is a comment.
    const std::string input =
        "profile p {\n"
        "  owner /home/*/.config/#308732 rw,  # a real trailing comment\n"
        "  owner /home/*/.config/#308735 rw,\n"
        "  /etc/a r,\n"
        "}\n";

    auto profs = parseText(input);
    REQUIRE(profs.size() == 1);
    REQUIRE(profs[0].rules.size() == 3); // not merged/blanked into bogus rules

    bool found = false;
    for (const auto& r : profs[0].rules)
        if (r.target == "/home/*/.config/#308732" && r.perms == "rw" && r.owner)
            found = true;
    CHECK(found);

    // The trailing comment is still stripped; the rule survives normalization.
    auto res = normalizeProfileText(input);
    CHECK(res.normalized.find("owner /home/*/.config/#308732 rw,") !=
          std::string::npos);
    CHECK(res.normalized.find("a real trailing comment") == std::string::npos);
}

TEST_CASE("a quoted path containing a comma/# is one rule, not split") {
    // The comma and '#' are inside the quotes; they must not terminate the rule
    // or start a comment.
    const std::string input =
        "profile p {\n"
        "  owner \"/home/*/Downloads/a, b #c.png\" r,\n"
        "  /etc/a r,\n"
        "}\n";

    auto profs = parseText(input);
    REQUIRE(profs.size() == 1);
    REQUIRE(profs[0].rules.size() == 2); // not split into 3+ bogus rules
    bool found = false;
    for (const auto& r : profs[0].rules)
        if (r.target == "\"/home/*/Downloads/a, b #c.png\"")
            found = true;
    CHECK(found);

    // Normalization keeps the quoted rule byte-for-byte.
    auto res = normalizeProfileText(input);
    CHECK(res.normalized.find("owner \"/home/*/Downloads/a, b #c.png\" r,") !=
          std::string::npos);
}

TEST_CASE("blank lines separate groups (kind / deny->allow)") {
    const std::string input =
        "profile p {\n"
        "  /a r,\n"
        "  capability net_raw,\n"
        "  deny /b w,\n"
        "}\n";
    auto res = normalizeProfileText(input);
    // capability, blank, deny block, blank, allow block.
    CHECK(res.normalized.find("\n\n") != std::string::npos);
}

TEST_CASE("normalization repairs unescaped peer labels that name a real profile") {
    // Three dead readby-rustrover rules (two quoted, one bare) - all unescaped,
    // so the kernel won't match them - plus a working escaped read rule.
    const std::string input =
        "profile jspawn /home/*/app/jspawnhelper {\n"
        "  ptrace (readby) peer=\"/home/*/app/rustrover\",\n"
        "  ptrace readby peer=/home/*/app/rustrover,\n"
        "  ptrace (readby) peer=\"/home/*/app/rustrover\",\n"
        "  ptrace read peer=/home/\\*/app/rustrover,\n"
        "}\n";

    // rustrover is a real loaded profile, so its peers should be repaired.
    std::set<std::string> known = {"/home/*/app/rustrover"};
    auto res = normalizeProfileText(input, known);
    REQUIRE(res.changed);

    // Every readby/read peer is now escaped, and the exact duplicates collapsed.
    auto profs = parseText(res.normalized);
    REQUIRE(profs.size() == 1);
    int readby = 0;
    for (const auto& r : profs[0].rules) {
        CHECK(r.raw.find("peer=/home/*/") == std::string::npos); // none unescaped
        if (r.raw.find("readby") != std::string::npos) {
            ++readby;
            CHECK(r.raw.find("peer=/home/\\*/app/rustrover") != std::string::npos);
        }
    }
    // The two identical quoted rules collapsed; the bare one differs in syntax,
    // so two distinct (now-escaped) readby rules remain.
    CHECK(readby == 2);
}

TEST_CASE("normalization leaves a peer glob alone when no profile has that name") {
    // No loaded profile named /home/*/app/other, so the '*' may be an intended
    // wildcard: do not touch it.
    const std::string input =
        "profile p /usr/bin/p {\n"
        "  ptrace (read) peer=/home/*/app/other,\n"
        "}\n";
    std::set<std::string> known = {"/usr/bin/p"};
    auto res = normalizeProfileText(input, known);
    CHECK(res.normalized.find("peer=/home/*/app/other") != std::string::npos);
}

TEST_CASE("a profile with no parseable content is returned unchanged") {
    const std::string input = "# just a comment\nabi <abi/3.0>,\n";
    auto res = normalizeProfileText(input);
    CHECK_FALSE(res.changed);
    CHECK(res.normalized == input);
}
