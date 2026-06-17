#pragma once

#include <cstddef>
#include <string>
#include <vector>

// A pragmatic parser for AppArmor profile files (the kind found under
// /etc/apparmor.d). It is intentionally lenient: it extracts the structure a
// human reviewer cares about — which profile attaches to what, and what access
// it *gives* (allow rules) versus *takes away* (deny rules) — rather than
// validating the full AppArmor grammar.
namespace apparmor {

// Whether a rule grants access or explicitly removes it.
enum class Decision { Allow, Deny };

// Coarse classification of a rule, used to group the "gives"/"takes" views.
enum class RuleKind {
    File,
    Capability,
    Network,
    Signal,
    Ptrace,
    Dbus,
    Unix,
    Mount,
    ChangeProfile,
    Link,
    Rlimit,
    Other,
};

const char* ruleKindName(RuleKind kind);

// Expand a file permission string (e.g. "rwmix") into a human description
// ("read, write, mmap, inherit-exec"). Returns an empty string if perms empty.
std::string describePerms(const std::string& perms);

// Translate an audit file mask (which may contain letters like 'c' create or
// 'd' delete that are not valid rule permissions) into the equivalent AppArmor
// rule permission string, de-duplicated and order-preserving. 'c'/'d' map to
// 'w'; unknown letters are dropped; 'w' subsumes 'a'.
std::string normalizeFilePerms(const std::string& mask);

struct Rule {
    Decision    decision = Decision::Allow;
    bool        audit    = false;  // rule was prefixed with "audit"
    bool        owner    = false;  // file rule was prefixed with "owner"
    RuleKind    kind     = RuleKind::Other;
    std::string target;            // path, capability name, or rule spec
    std::string perms;             // file rules only (e.g. "rwmix"); else empty
    std::string raw;               // original rule text, trailing comma removed
    int         line     = 0;
    // Byte range [startOffset, endOffset) of the rule text in the source
    // (excluding the terminating comma). Valid against the original file thanks
    // to length-preserving comment stripping. Used to rewrite a rule in place.
    std::size_t startOffset = 0;
    std::size_t endOffset   = 0;
};

struct Profile {
    std::string name;                    // profile name
    std::string attachment;              // attachment path, if any
    std::vector<std::string> flags;      // e.g. "complain", "attach_disconnected"
    std::vector<std::string> includes;   // abstraction/local includes
    std::vector<Rule>        rules;
    std::vector<Profile>     children;   // nested child profiles / hats
    std::string sourceFile;              // file the profile was read from
    int         startLine = 0;
    // Byte offset of this profile body's closing '}' in the source text. Used
    // to insert new rules just before it. Length-preserving comment stripping
    // keeps this valid against the original file.
    std::size_t bodyEndOffset = 0;

    bool complain() const;               // runs in complain (log-only) mode
    std::size_t allowCount() const;      // allow rules at this level
    std::size_t denyCount() const;       // deny rules at this level
};

struct ParseResult {
    std::vector<Profile>     profiles;   // top-level profiles, sorted by name
    std::vector<std::string> errors;     // unreadable files, etc.
    std::size_t              filesParsed = 0;
    std::string              directory;  // the directory that was parsed
};

// List the candidate top-level profile files in a directory (full paths,
// sorted; non-recursive, skipping README/backups and subdirectories).
std::vector<std::string> listProfileFiles(const std::string& dir);

// Parse every top-level profile file in a directory (non-recursive; the
// abstractions/, tunables/, abi/, … subdirectories are not profiles).
ParseResult parseDirectory(const std::string& dir);

// Parse profile text directly (used by the tests and by parseDirectory).
std::vector<Profile> parseText(const std::string& text,
                               const std::string& sourceFile = "");

} // namespace apparmor
