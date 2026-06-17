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
