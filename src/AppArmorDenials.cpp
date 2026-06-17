#include "AppArmorDenials.h"

#include <algorithm>
#include <map>

namespace apparmor {
namespace {

std::string strOr(std::optional<std::string_view> v) {
    return v ? std::string(*v) : std::string();
}

const audit::Record* findAvc(const audit::Event& ev) {
    for (const auto& r : ev.records)
        if (r.type == "AVC")
            return &r;
    return nullptr;
}

// Wildcard match for a brace-free pattern ('?', '*', '**').
bool wildMatch(const char* p, const char* t) {
    while (*p) {
        if (*p == '*') {
            const bool dbl = (p[1] == '*');
            const char* pn = p + (dbl ? 2 : 1);
            if (*pn == '\0') {
                // Trailing star: '**' swallows the rest; '*' must not cross '/'.
                if (dbl)
                    return true;
                for (const char* tt = t; *tt; ++tt)
                    if (*tt == '/')
                        return false;
                return true;
            }
            for (const char* tt = t;; ++tt) {
                if (wildMatch(pn, tt))
                    return true;
                if (*tt == '\0')
                    return false;
                if (!dbl && *tt == '/')
                    return false; // '*' stops at a path separator
            }
        }
        if (*p == '?') {
            if (*t == '\0' || *t == '/')
                return false;
            ++p;
            ++t;
            continue;
        }
        if (*p != *t)
            return false;
        ++p;
        ++t;
    }
    return *t == '\0';
}

// Expand the first {a,b,c} alternation into separate brace-free-er patterns.
void expandBraces(const std::string& pattern, std::vector<std::string>& out) {
    const auto open = pattern.find('{');
    if (open == std::string::npos) {
        out.push_back(pattern);
        return;
    }
    // Find the matching close brace, honouring nesting.
    int depth = 0;
    std::size_t close = std::string::npos;
    for (std::size_t i = open; i < pattern.size(); ++i) {
        if (pattern[i] == '{')
            ++depth;
        else if (pattern[i] == '}' && --depth == 0) {
            close = i;
            break;
        }
    }
    if (close == std::string::npos) { // unbalanced; treat literally
        out.push_back(pattern);
        return;
    }

    const std::string prefix = pattern.substr(0, open);
    const std::string suffix = pattern.substr(close + 1);
    const std::string body = pattern.substr(open + 1, close - open - 1);

    // Split body on top-level commas.
    std::vector<std::string> options;
    int d = 0;
    std::string cur;
    for (char c : body) {
        if (c == '{')
            ++d;
        else if (c == '}')
            --d;
        if (c == ',' && d == 0) {
            options.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    options.push_back(cur);

    for (const auto& opt : options)
        expandBraces(prefix + opt + suffix, out);
}

// Do two AppArmor permission/mask strings share at least one letter?
bool masksOverlap(const std::string& a, const std::string& b) {
    for (char c : a)
        if (b.find(c) != std::string::npos)
            return true;
    return false;
}

// Find a profile (recursively) whose name or attachment equals the denied
// profile string.
const Profile* findProfile(const std::vector<Profile>& profiles,
                           const std::string& name) {
    for (const auto& p : profiles) {
        if (p.name == name || (!p.attachment.empty() && p.attachment == name))
            return &p;
        if (const Profile* c = findProfile(p.children, name))
            return c;
    }
    return nullptr;
}

RuleKind kindForOperation(const Denial& d) {
    if (d.klass == "file" || (!d.target.empty() && d.target[0] == '/'))
        return RuleKind::File;
    if (d.operation == "ptrace" || d.klass == "ptrace")
        return RuleKind::Ptrace;
    if (d.operation == "signal" || d.klass == "signal")
        return RuleKind::Signal;
    return RuleKind::Other;
}

} // namespace

const char* correlationName(Correlation c) {
    switch (c) {
    case Correlation::Unknown:      return "profile not loaded";
    case Correlation::ExplicitDeny: return "explicit deny rule";
    case Correlation::Implicit:     return "implicit (no allow)";
    }
    return "";
}

bool globMatch(const std::string& pattern, const std::string& text) {
    std::vector<std::string> expanded;
    expandBraces(pattern, expanded);
    for (const auto& pat : expanded)
        if (wildMatch(pat.c_str(), text.c_str()))
            return true;
    return false;
}

std::optional<Denial> denialFromEvent(const audit::Event& event) {
    const audit::Record* avc = findAvc(event);
    if (!avc)
        return std::nullopt;
    if (strOr(avc->getResolved("apparmor")) != "DENIED")
        return std::nullopt;

    Denial d;
    d.profile = strOr(avc->get("profile"));
    d.operation = strOr(avc->get("operation"));
    d.klass = strOr(avc->get("class"));
    d.requestedMask = strOr(avc->get("requested_mask"));
    d.deniedMask = strOr(avc->get("denied_mask"));
    d.comm = strOr(avc->getResolved("comm"));
    d.pid = strOr(avc->get("pid"));
    d.timestamp = event.timestamp;

    if (auto name = avc->get("name"))
        d.target = std::string(*name);
    else if (auto peer = avc->get("peer"))
        d.target = std::string(*peer);

    return d;
}

std::vector<DenialGroup> aggregateDenials(const std::vector<Denial>& denials) {
    std::map<std::string, DenialGroup> groups;
    for (const auto& d : denials) {
        const std::string key = d.profile + '\x1f' + d.operation + '\x1f' +
                                d.target + '\x1f' + d.deniedMask;
        auto [it, inserted] = groups.try_emplace(key);
        DenialGroup& g = it->second;
        if (inserted) {
            g.sample = d;
            g.firstSeen = d.timestamp;
            g.lastSeen = d.timestamp;
        }
        ++g.count;
        g.firstSeen = std::min(g.firstSeen, d.timestamp);
        g.lastSeen = std::max(g.lastSeen, d.timestamp);
    }

    std::vector<DenialGroup> out;
    out.reserve(groups.size());
    for (auto& [_, g] : groups)
        out.push_back(std::move(g));
    std::sort(out.begin(), out.end(),
              [](const DenialGroup& a, const DenialGroup& b) {
                  if (a.count != b.count)
                      return a.count > b.count;
                  return a.sample.profile < b.sample.profile;
              });
    return out;
}

void correlate(std::vector<DenialGroup>& groups,
               const std::vector<Profile>& profiles) {
    for (auto& g : groups) {
        const Profile* prof = findProfile(profiles, g.sample.profile);
        if (!prof) {
            g.correlation = Correlation::Unknown;
            continue;
        }

        const RuleKind wantKind = kindForOperation(g.sample);
        const Rule* match = nullptr;
        for (const auto& r : prof->rules) {
            if (r.decision != Decision::Deny || r.kind != wantKind)
                continue;
            if (wantKind == RuleKind::File) {
                if (!globMatch(r.target, g.sample.target))
                    continue;
                // A perm-less deny (deny <path>,) covers everything; otherwise
                // the denied mask must overlap the rule's permissions.
                if (!r.perms.empty() &&
                    !masksOverlap(r.perms, g.sample.deniedMask))
                    continue;
            }
            match = &r;
            break;
        }

        if (match) {
            g.correlation = Correlation::ExplicitDeny;
            g.matchedRule = match->raw;
        } else {
            g.correlation = Correlation::Implicit;
        }
    }
}

} // namespace apparmor
