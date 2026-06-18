#pragma once

#include <string>

// Normalizes an AppArmor profile file to a canonical form: rule statements
// within each profile are de-duplicated, file rules for the same path are
// merged (their permissions combined), and rules are sorted into a canonical
// order (by kind, then target).
//
// Regeneration is conservative about everything that is *not* a rule: the file
// preamble (abi, tunables, variables, comments before the first profile), each
// profile's header line, its `include` statements and any nested child profiles
// are preserved verbatim. Only the rule lines are rewritten, and comments that
// sit *inside* a profile body are dropped (they cannot be reattached after
// reordering) - which is why the UI shows a diff before applying.
namespace apparmor {

struct NormalizationResult {
    bool        changed = false;  // the normalized text differs from the input
    std::string normalized;       // the full normalized file text
    std::string diff;             // unified-style line diff (original -> normalized)
};

NormalizationResult normalizeProfileText(const std::string& fileText);

} // namespace apparmor
