#pragma once

#include <string>

// Validates AppArmor profile files using the real `apparmor_parser` tool, so
// the verdict matches what the parser itself accepts.
namespace apparmor {

struct ValidationResult {
    std::string file;    // full path of the profile file
    bool        ok = false;
    std::string output;  // apparmor_parser's diagnostics (errors); empty if ok
};

// True if the apparmor_parser executable is available on PATH / usual locations.
bool validatorAvailable();

// Validate a single profile file with `apparmor_parser -Q --skip-cache <file>`:
// compile it (resolving includes) without loading into the kernel and without
// touching the policy cache, so it works as a normal user. ok == compiled
// cleanly; output carries the parser's error text otherwise.
ValidationResult validateProfile(const std::string& fullPath);

} // namespace apparmor
