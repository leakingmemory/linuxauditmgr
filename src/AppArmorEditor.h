#pragma once

#include <optional>
#include <string>

#include "AppArmorDenials.h"
#include "AppArmorParser.h"

// Adds allow/deny rules to AppArmor profile files in response to a denial.
//
// Writes are crash-safe: the new contents go to a temporary file in the same
// directory, are fsync'd and re-parsed for validity, and only then atomically
// rename()d over the original. The original is never modified in place, so a
// crash mid-write cannot corrupt or lose it.
namespace apparmor {

// Build the AppArmor rule text (terminated with a comma) that would allow or
// deny the access described by a denial. Returns nullopt for denial classes we
// do not know how to express (the caller should not offer the action then).
std::optional<std::string> buildRule(const Denial& denial, Decision decision);

// Add (owner=true) or remove (owner=false) the `owner` qualifier on a rule,
// preserving AppArmor's qualifier order ([audit] [deny|allow] owner <body>).
// Idempotent and safe on rules that already do (not) carry it; lets the UI flip
// an owner-conditional rule to apply to any user, or vice versa.
std::string setOwnerQualifier(const std::string& ruleText, bool owner);

// True if `rule` is a file rule - the only kind the `owner` qualifier applies
// to - so the UI knows whether to offer an owner/any toggle.
bool ruleSupportsOwner(const std::string& ruleText);

// For a peer-mediated denial (ptrace/signal), build the COMPLEMENTARY rule the
// PEER profile needs - AppArmor mediates these on both ends, so allowing the
// access in only one profile is not enough. The access mode is inverted
// (read<->readby, trace<->tracedby, send<->receive) and the peer becomes the
// denial's own profile. Returns nullopt when the denial is not peer-mediated,
// the peer is unconfined, or the inverse mode is unknown.
std::optional<std::string> buildPeerRule(const Denial& denial, Decision decision);

struct EditResult {
    bool        ok = false;
    std::string message;   // human-readable success or error description
    std::string rule;      // the rule that was (or would have been) added
};

// Insert `rule` into the named profile in `file`, crash-safely. The file is
// re-parsed to find the profile and to validate the result before replacing.
EditResult addRuleToProfile(const std::string& file,
                            const std::string& profileName,
                            const std::string& rule);

// Reverse an explicit deny rule into an allow, crash-safely: find the rule in
// the named profile whose text matches `denyRuleRaw` (e.g. the matched rule of
// an "explicit deny" denial) and rewrite it in place with the leading `deny`
// qualifier removed. The file is re-parsed to validate before replacing.
EditResult reverseDenyRule(const std::string& file,
                           const std::string& profileName,
                           const std::string& denyRuleRaw);

// Crash-safely replace a file's contents: write to a temp file in the same
// directory, fsync, verify the bytes, preserve permissions, then atomically
// rename over the original. Returns false (with `error` set) on failure,
// leaving the original untouched.
bool writeFileAtomically(const std::string& file, const std::string& content,
                         std::string& error);

// True if the process can load profiles into the kernel (i.e. runs as root).
bool canReloadProfiles();

struct ReloadResult {
    bool        ok = false;
    std::string message;
};

// Reload (replace) a profile into the kernel with `apparmor_parser -r <file>`.
// Requires root; captures the parser's output on failure.
ReloadResult reloadProfile(const std::string& file);

} // namespace apparmor
