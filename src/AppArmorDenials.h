#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "AppArmorParser.h"
#include "AuditParser.h"

// Correlates AppArmor "DENIED" events from the audit log with the deny rules in
// the loaded profiles, to answer "which denials are happening, and which are an
// explicit deny rule versus an implicit (nothing-allowed-it) denial".
namespace apparmor {

// A single AppArmor DENIED record extracted from an audit event.
struct Denial {
    std::string profile;       // the confined profile that was denied
    std::string operation;     // ptrace, open, link, signal, ...
    std::string klass;         // "file", "ptrace", "signal", ...
    std::string target;        // denied path (file ops) or peer (ptrace/signal)
    std::string requestedMask; // e.g. "r", "wr", "readby"
    std::string deniedMask;
    std::string comm;
    std::string pid;
    double      timestamp = 0.0;
};

// Extract an AppArmor denial from a parsed audit event, or nullopt if the event
// is not an AppArmor DENIED record.
std::optional<Denial> denialFromEvent(const audit::Event& event);

// Extract an AppArmor ALLOWED record (logged in complain mode, or by an `audit`
// allow rule) into the same structure, or nullopt if it is not one.
std::optional<Denial> allowFromEvent(const audit::Event& event);

// How a group relates to the loaded profiles. The first three describe denials,
// the last two describe allows.
enum class Correlation {
    Unknown,       // the profile was not found among the loaded profiles
    ExplicitDeny,  // an explicit `deny` rule in the profile matches
    Implicit,      // no rule allowed it (a silent/default denial)
    AllowedByRule, // an explicit allow rule in the profile matches
    ComplainOnly,  // allowed only because the profile is in complain mode
};

const char* correlationName(Correlation c);

// Identical denials collapsed together, with a count and time span.
struct DenialGroup {
    Denial      sample;
    std::size_t count = 0;
    double      firstSeen = 0.0;
    double      lastSeen = 0.0;
    Correlation correlation = Correlation::Unknown;
    std::string matchedRule;  // raw text of the matching deny rule, if any
    std::string profileFile;  // source file of the matched profile (for editing)
};

// Collapse identical denials (same profile/operation/target/denied mask).
// Result is sorted by descending count.
std::vector<DenialGroup> aggregateDenials(const std::vector<Denial>& denials);

// Set each group's correlation/matchedRule against the loaded profiles, looking
// for matching deny rules (for denial groups).
void correlate(std::vector<DenialGroup>& groups,
               const std::vector<Profile>& profiles);

// Same, for allow groups: looks for a matching allow rule (AllowedByRule),
// otherwise flags entries permitted only because the profile is in complain
// mode (ComplainOnly).
void correlateAllows(std::vector<DenialGroup>& groups,
                     const std::vector<Profile>& profiles);

// AppArmor-style glob match. Supports '?', '*' (does not cross '/'), '**'
// (crosses '/') and '{a,b,c}' alternation. Used to match denied paths against
// file rule patterns.
bool globMatch(const std::string& pattern, const std::string& text);

} // namespace apparmor
