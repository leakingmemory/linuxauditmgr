#include "AppArmorNormalizer.h"

#include <algorithm>
#include <map>
#include <set>
#include <vector>

#include "AppArmorParser.h"

namespace apparmor {
namespace {

// Strip one layer of surrounding quotes and all backslash escapes from a peer=
// value, yielding the literal profile name it refers to.
std::string unescapePeerValue(std::string v) {
    if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
        v = v.substr(1, v.size() - 2);
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (v[i] == '\\' && i + 1 < v.size())
            out += v[++i];
        else
            out += v[i];
    }
    return out;
}

// If a ptrace/signal rule's peer= label names a real loaded profile but is
// written with unescaped glob metacharacters (so the kernel will not match it),
// rewrite the peer to the escaped form that matches. Profiles whose names use
// @{...} variable expansions are left alone (escaping would break the variable).
std::string canonicalizePeer(const std::string& raw,
                             const std::set<std::string>& known) {
    const std::string key = "peer=";
    const auto pos = raw.find(key);
    if (pos == std::string::npos)
        return raw;
    const std::size_t vstart = pos + key.size();
    const std::string value = raw.substr(vstart); // peer is the last token
    if (value.empty() || value == "unconfined" ||
        value.find("@{") != std::string::npos)
        return raw;

    const std::string literal = unescapePeerValue(value);
    if (!known.count(literal))
        return raw; // not a known profile name: leave intentional globs alone

    const std::string fixed = escapePeerLabel(literal);
    if (fixed == value)
        return raw; // already canonical
    return raw.substr(0, vstart) + fixed;
}

// Produce the normalized rule lines (each terminated with a comma) for one
// profile: simple file rules for the same path/qualifiers merged, exact
// duplicates removed, everything sorted by (kind, target).
std::vector<std::string> normalizedRuleLines(
    const Profile& p, const std::set<std::string>& known) {
    struct Entry {
        int         ord;
        int         dec;  // deny (0) sorts before allow (1), like aa-tools
        std::string text;
    };
    std::vector<Entry> entries;
    auto decRank = [](Decision d) { return d == Decision::Deny ? 0 : 1; };

    auto isExec = [](const std::string& perms) {
        return perms.find('x') != std::string::npos;
    };
    // Only plain file rules (no exec transition, no "-> target", no quoting) are
    // merged and rebuilt; everything else is kept verbatim so we never have to
    // re-quote or re-escape a path and risk corrupting it.
    auto mergeable = [&](const Rule& r) {
        return r.kind == RuleKind::File && !r.target.empty() &&
               !r.perms.empty() && !isExec(r.perms) &&
               r.raw.find("->") == std::string::npos &&
               r.raw.find('"') == std::string::npos;
    };

    std::map<std::string, std::pair<std::string, const Rule*>> merged; // key->(perms,rep)
    std::vector<const Rule*> verbatim;
    for (const auto& r : p.rules) {
        if (mergeable(r)) {
            const std::string key = std::string(1, r.decision == Decision::Deny
                                                       ? 'd' : 'a') +
                                    (r.audit ? 'A' : '_') +
                                    (r.owner ? 'O' : '_') + '\x1f' + r.target;
            auto it = merged.find(key);
            if (it == merged.end())
                merged.emplace(key, std::make_pair(r.perms, &r));
            else
                it->second.first += r.perms;
        } else {
            verbatim.push_back(&r);
        }
    }

    for (const auto& [key, val] : merged) {
        const Rule& r = *val.second;
        std::string text;
        if (r.audit)
            text += "audit ";
        if (r.decision == Decision::Deny)
            text += "deny ";
        if (r.owner)
            text += "owner ";
        text += r.target + ' ' + normalizeFilePerms(val.first) + ',';
        entries.push_back({ruleKindOrder(RuleKind::File), decRank(r.decision), text});
    }

    std::set<std::string> seen;
    for (const Rule* r : verbatim) {
        // Repair a ptrace/signal peer that won't match because its glob
        // metacharacters were not escaped; this also makes otherwise-distinct
        // dead duplicates collapse below.
        std::string raw = r->raw;
        if (r->kind == RuleKind::Ptrace || r->kind == RuleKind::Signal)
            raw = canonicalizePeer(raw, known);
        if (!seen.insert(raw).second)
            continue; // exact duplicate
        entries.push_back(
            {ruleKindOrder(r->kind), decRank(r->decision), raw + ','});
    }

    // Sort like aa-tools' get_clean(): by kind, deny before allow, then by the
    // rendered rule text. Because the text starts with the `owner ` prefix for
    // owner rules, this groups all owner rules together (after the non-owner
    // ones) rather than interleaving them by path.
    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
        if (a.ord != b.ord)
            return a.ord < b.ord;
        if (a.dec != b.dec)
            return a.dec < b.dec;
        return a.text < b.text;
    });

    // Emit, with a blank line between groups (a change of kind, or deny->allow
    // within a kind), matching the spacing the apparmor utils produce. Empty
    // strings denote blank lines.
    std::vector<std::string> out;
    int prevOrd = -1, prevDec = -1;
    for (std::size_t k = 0; k < entries.size(); ++k) {
        if (k > 0 && (entries[k].ord != prevOrd || entries[k].dec != prevDec))
            out.emplace_back();
        out.push_back(std::move(entries[k].text));
        prevOrd = entries[k].ord;
        prevDec = entries[k].dec;
    }
    return out;
}

// Regenerate a profile block: header verbatim, then includes (verbatim, in
// order), then normalized rules, then nested children (recursively). Returns the
// block text ending with the closing '}', with no trailing newline.
std::string renderProfile(const Profile& p, const std::string& text, int lvl,
                          const std::set<std::string>& known) {
    const std::string pad(static_cast<std::size_t>(lvl) * 2, ' ');
    const std::string cpad(static_cast<std::size_t>(lvl + 1) * 2, ' ');

    std::string out = pad + text.substr(p.headerStartOffset,
                                        p.openBraceOffset - p.headerStartOffset +
                                            1);
    // `include if exists <local/...>` is a site-override trailer and must stay
    // at the end; other includes (abstractions) go at the top.
    std::vector<const std::string*> topIncludes, localIncludes;
    for (const auto& inc : p.includeLines)
        (inc.find("local/") != std::string::npos ? localIncludes : topIncludes)
            .push_back(&inc);

    // A blank line never carries indentation (matches aa-tools' output).
    auto emit = [&](const std::string& line) {
        out += '\n' + (line.empty() ? std::string() : cpad + line);
    };

    for (const auto* inc : topIncludes)
        emit(*inc);
    const auto rules = normalizedRuleLines(p, known);
    if (!topIncludes.empty() && !rules.empty())
        emit(""); // blank line between the include block and the rules
    for (const auto& rule : rules)
        emit(rule);
    for (const auto& child : p.children) {
        emit("");
        out += renderProfile(child, text, lvl + 1, known);
    }
    for (const auto* inc : localIncludes) {
        emit("");
        emit(*inc);
    }
    // aa-tools leave a blank line before the closing brace when the body has
    // any content.
    const bool hasBody = !topIncludes.empty() || !rules.empty() ||
                         !p.children.empty() || !localIncludes.empty();
    if (hasBody)
        emit("");
    out += '\n' + pad + '}';
    return out;
}

std::vector<std::string> splitLines(const std::string& s) {
    std::vector<std::string> lines;
    std::string cur;
    for (char c : s) {
        if (c == '\n') {
            lines.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty())
        lines.push_back(cur);
    return lines;
}

// A simple LCS-based line diff with '-'/'+'/' ' prefixes; long runs of
// unchanged lines are collapsed for readability.
std::string lineDiff(const std::string& aText, const std::string& bText) {
    const std::vector<std::string> a = splitLines(aText);
    const std::vector<std::string> b = splitLines(bText);
    const std::size_t n = a.size(), m = b.size();

    std::vector<std::vector<int>> dp(n + 1, std::vector<int>(m + 1, 0));
    for (std::size_t i = n; i-- > 0;)
        for (std::size_t j = m; j-- > 0;)
            dp[i][j] = (a[i] == b[j]) ? dp[i + 1][j + 1] + 1
                                      : std::max(dp[i + 1][j], dp[i][j + 1]);

    std::vector<std::pair<char, std::string>> ops;
    std::size_t i = 0, j = 0;
    while (i < n && j < m) {
        if (a[i] == b[j]) {
            ops.push_back({' ', a[i]});
            ++i;
            ++j;
        } else if (dp[i + 1][j] >= dp[i][j + 1]) {
            ops.push_back({'-', a[i++]});
        } else {
            ops.push_back({'+', b[j++]});
        }
    }
    for (; i < n; ++i)
        ops.push_back({'-', a[i]});
    for (; j < m; ++j)
        ops.push_back({'+', b[j]});

    std::string out;
    for (std::size_t k = 0; k < ops.size();) {
        if (ops[k].first != ' ') {
            out += ops[k].first;
            out += ops[k].second;
            out += '\n';
            ++k;
            continue;
        }
        // Collapse a run of unchanged lines longer than 6.
        std::size_t run = k;
        while (run < ops.size() && ops[run].first == ' ')
            ++run;
        const std::size_t len = run - k;
        auto emit = [&](std::size_t idx) {
            out += ' ';
            out += ops[idx].second;
            out += '\n';
        };
        if (len <= 6) {
            for (std::size_t x = k; x < run; ++x)
                emit(x);
        } else {
            emit(k);
            emit(k + 1);
            out += "  ... " + std::to_string(len - 4) + " unchanged lines ...\n";
            emit(run - 2);
            emit(run - 1);
        }
        k = run;
    }
    return out;
}

} // namespace

NormalizationResult normalizeProfileText(
    const std::string& fileText, const std::set<std::string>& knownProfileNames) {
    NormalizationResult res;
    res.normalized = fileText;

    auto profiles = parseText(fileText);
    if (profiles.empty())
        return res; // nothing parseable to normalize

    std::string out;
    std::size_t cursor = 0;
    for (const auto& p : profiles) {
        if (p.openBraceOffset == 0 || p.bodyEndOffset == 0 ||
            p.headerStartOffset < cursor ||
            p.bodyEndOffset >= fileText.size())
            return res; // unexpected offsets; refuse to rewrite
        out += fileText.substr(cursor, p.headerStartOffset - cursor);
        out += renderProfile(p, fileText, 0, knownProfileNames);
        cursor = p.bodyEndOffset + 1;
    }
    out += fileText.substr(std::min(cursor, fileText.size()));

    res.normalized = out;
    res.changed = (out != fileText);
    if (res.changed)
        res.diff = lineDiff(fileText, out);
    return res;
}

} // namespace apparmor
