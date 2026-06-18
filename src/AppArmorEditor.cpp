#include "AppArmorEditor.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace apparmor {
namespace {

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

std::string readFile(const std::string& path, bool& ok) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        ok = false;
        return {};
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    ok = true;
    return ss.str();
}

bool isAllSpace(std::string_view s) {
    for (char c : s)
        if (c != ' ' && c != '\t')
            return false;
    return true;
}

// Quote an AppArmor value that contains whitespace; leave it bare otherwise.
std::string maybeQuote(const std::string& s) {
    if (s.find_first_of(" \t") != std::string::npos)
        return '"' + s + '"';
    return s;
}

// peer= values are profile names; quote them unless they are the special
// "unconfined" keyword.
std::string peerToken(const std::string& peer) {
    if (peer.empty() || peer == "unconfined")
        return peer;
    return '"' + peer + '"';
}

RuleKind kindForDenial(const Denial& d) {
    // The class/operation determines the rule kind; only fall back to the path
    // heuristic when neither says otherwise (a ptrace/signal peer can itself be
    // a path, so the '/' test must not come first).
    if (d.klass == "file")
        return RuleKind::File;
    if (d.operation == "ptrace" || d.klass == "ptrace")
        return RuleKind::Ptrace;
    if (d.operation == "signal" || d.klass == "signal")
        return RuleKind::Signal;
    if (!d.target.empty() && d.target[0] == '/')
        return RuleKind::File;
    return RuleKind::Other;
}

// Crash-safe replace: write `content` to a temp file in the same directory,
// fsync it, verify the bytes, preserve permissions, then atomically rename it
// over `file`. The original is never modified in place. Returns false (with
// `err` set) on any failure, leaving the original untouched.
bool atomicReplace(const std::string& file, const std::string& content,
                   std::string& err) {
    namespace fs = std::filesystem;
    const fs::path target(file);
    const fs::path tmp =
        target.parent_path() /
        (target.filename().string() + ".aatmp." + std::to_string(::getpid()));

    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        err = "Cannot create temp file " + tmp.string() + ": " +
              std::strerror(errno);
        return false;
    }
    auto fail = [&](const std::string& msg) {
        ::close(fd);
        ::unlink(tmp.c_str());
        err = msg;
        return false;
    };

    std::size_t written = 0;
    while (written < content.size()) {
        ssize_t n =
            ::write(fd, content.data() + written, content.size() - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return fail(std::string("write failed: ") + std::strerror(errno));
        }
        written += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0)
        return fail(std::string("fsync failed: ") + std::strerror(errno));

    struct stat st{};
    if (::stat(file.c_str(), &st) == 0)
        ::fchmod(fd, st.st_mode & 0777);
    ::close(fd);

    // Verify the bytes on disk before replacing anything.
    bool vok = false;
    if (const std::string back = readFile(tmp.string(), vok);
        !vok || back != content) {
        ::unlink(tmp.c_str());
        err = "Verification of the temp file failed; file left unchanged";
        return false;
    }

    if (::rename(tmp.c_str(), file.c_str()) != 0) {
        const std::string msg =
            std::string("rename failed: ") + std::strerror(errno);
        ::unlink(tmp.c_str());
        err = msg;
        return false;
    }

    // Persist the directory entry so the rename survives a crash.
    if (int dfd = ::open(target.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
        dfd >= 0) {
        ::fsync(dfd);
        ::close(dfd);
    }
    return true;
}

// A pending text edit on the original file: replace [start, end) with repl.
struct Edit {
    std::size_t start;
    std::size_t end;
    std::string repl;
};

// Parse a single rule's text (e.g. "/etc/foo rw,") into its structured form.
std::optional<Rule> parseSingleRule(const std::string& ruleText) {
    auto profs = parseText("profile __aa_tmp__ {\n" + ruleText + "\n}\n", "");
    if (profs.empty() || profs.front().rules.empty())
        return std::nullopt;
    return profs.front().rules.front();
}

// Permissions in `perms` that are not in `remove`, order preserved.
std::string subtractPerms(const std::string& perms, const std::string& remove) {
    std::string out;
    for (char c : perms)
        if (remove.find(c) == std::string::npos)
            out.push_back(c);
    return out;
}

// A target with no glob metacharacters; only such existing rules are safe to
// subsume, since "new pattern matches this exact path" is then sound coverage.
bool isConcretePath(const std::string& s) {
    return s.find_first_of("*?{}[]") == std::string::npos;
}

// Byte range [start, end) of a file rule's permission token in the source.
std::pair<std::size_t, std::size_t> locatePermsToken(const std::string& text,
                                                     const Rule& r) {
    std::vector<std::pair<std::size_t, std::size_t>> toks;
    std::size_t i = r.startOffset;
    const std::size_t n = std::min(r.endOffset, text.size());
    while (i < n) {
        while (i < n && std::isspace(static_cast<unsigned char>(text[i])))
            ++i;
        const std::size_t s = i;
        while (i < n && !std::isspace(static_cast<unsigned char>(text[i])))
            ++i;
        if (i > s)
            toks.push_back({s, i});
    }
    std::size_t idx = 0;
    auto tok = [&](std::size_t k) {
        return text.substr(toks[k].first, toks[k].second - toks[k].first);
    };
    while (idx < toks.size()) {
        const std::string t = tok(idx);
        if (t == "audit" || t == "deny" || t == "allow" || t == "owner")
            ++idx;
        else
            break;
    }
    // idx -> path token, idx + 1 -> perms token.
    if (idx + 1 < toks.size())
        return toks[idx + 1];
    return {std::string::npos, std::string::npos};
}

// Whole-line byte range [start, end) containing a rule (incl. trailing newline).
std::pair<std::size_t, std::size_t> ruleLineRange(const std::string& text,
                                                  const Rule& r) {
    std::size_t ds = text.rfind('\n', r.startOffset);
    ds = (ds == std::string::npos) ? 0 : ds + 1;
    std::size_t de = text.find('\n', r.endOffset);
    de = (de == std::string::npos) ? text.size() : de + 1;
    return {ds, de};
}

} // namespace

std::optional<std::string> buildRule(const Denial& d, Decision decision) {
    const std::string prefix = (decision == Decision::Deny) ? "deny " : "";
    const std::string mask = !d.deniedMask.empty() ? d.deniedMask
                                                   : d.requestedMask;

    switch (kindForDenial(d)) {
    case RuleKind::File: {
        // The audit mask may carry letters ('c' create, 'd' delete) that are
        // not valid rule permissions; translate to a real permission string.
        const std::string perms = normalizeFilePerms(mask);
        if (d.target.empty() || perms.empty())
            return std::nullopt;
        // Qualifier order is `[deny] [owner] <path> <perms>,`. Emit `owner` when
        // the access was to a file the task owns (fsuid == ouid), matching the
        // tighter rule aa-logprof would suggest.
        const std::string ownerKw = d.owner ? "owner " : "";
        return prefix + ownerKw + maybeQuote(d.target) + ' ' + perms + ',';
    }
    case RuleKind::Ptrace: {
        std::string rule = prefix + "ptrace";
        if (!mask.empty())
            rule += " (" + mask + ")";
        if (!d.target.empty())
            rule += " peer=" + peerToken(d.target);
        return rule + ',';
    }
    case RuleKind::Signal: {
        std::string rule = prefix + "signal";
        if (!mask.empty())
            rule += " (" + mask + ")";
        if (!d.target.empty())
            rule += " peer=" + peerToken(d.target);
        return rule + ',';
    }
    default:
        return std::nullopt;
    }
}

std::string setOwnerQualifier(const std::string& ruleText, bool owner) {
    const std::size_t n = ruleText.size();
    auto isws = [](char c) { return std::isspace(static_cast<unsigned char>(c)) != 0; };

    std::size_t scan = 0;
    while (scan < n && isws(ruleText[scan]))
        ++scan;
    const std::string indent = ruleText.substr(0, scan);

    // Walk the leading qualifiers, keeping audit/deny/allow in their original
    // order and dropping any existing owner (we re-add it from `owner`). The
    // body is whatever follows the qualifiers.
    std::vector<std::string> quals;
    std::size_t i = scan;
    std::size_t bodyStart = scan;
    while (i < n) {
        const std::size_t tokStart = i;
        while (i < n && !isws(ruleText[i]))
            ++i;
        const std::string tok = ruleText.substr(tokStart, i - tokStart);
        if (tok == "audit" || tok == "deny" || tok == "allow") {
            quals.push_back(tok);
        } else if (tok != "owner") {
            bodyStart = tokStart; // first non-qualifier token: the rule body
            break;
        }
        while (i < n && isws(ruleText[i]))
            ++i;
        bodyStart = i;
    }

    std::string out = indent;
    for (const auto& q : quals)
        out += q + ' ';
    if (owner)
        out += "owner ";
    out += ruleText.substr(bodyStart);
    return out;
}

bool ruleSupportsOwner(const std::string& ruleText) {
    auto r = parseSingleRule(ruleText);
    return r && r->kind == RuleKind::File;
}

std::optional<std::string> buildPeerRule(const Denial& d, Decision decision) {
    const RuleKind k = kindForDenial(d);
    if (k != RuleKind::Ptrace && k != RuleKind::Signal)
        return std::nullopt;
    // Need a confined peer (it becomes the rule's profile) and our own profile
    // (it becomes the rule's peer). An unconfined peer is not mediated.
    if (d.target.empty() || d.target == "unconfined" || d.profile.empty())
        return std::nullopt;

    const std::string mask =
        !d.deniedMask.empty() ? d.deniedMask : d.requestedMask;
    auto inverse = [](const std::string& m) -> std::string {
        if (m == "read")     return "readby";
        if (m == "readby")   return "read";
        if (m == "trace")    return "tracedby";
        if (m == "tracedby") return "trace";
        if (m == "send")     return "receive";
        if (m == "receive")  return "send";
        return {};
    };
    const std::string inv = inverse(mask);
    if (inv.empty())
        return std::nullopt;

    const std::string prefix = (decision == Decision::Deny) ? "deny " : "";
    const char* kw = (k == RuleKind::Ptrace) ? "ptrace" : "signal";
    return prefix + kw + " (" + inv + ") peer=" + peerToken(d.profile) + ',';
}

EditResult addRuleToProfile(const std::string& file,
                            const std::string& profileName,
                            const std::string& rule) {
    EditResult res;
    res.rule = rule;

    bool ok = false;
    const std::string original = readFile(file, ok);
    if (!ok) {
        res.message = "Cannot read " + file;
        return res;
    }

    auto profiles = parseText(original, file);
    const Profile* prof = findProfile(profiles, profileName);
    if (!prof) {
        res.message = "Profile '" + profileName + "' not found in " + file;
        return res;
    }
    if (prof->bodyEndOffset == 0 || prof->bodyEndOffset >= original.size()) {
        res.message = "Could not locate the body of profile '" + profileName +
                      "'";
        return res;
    }

    std::vector<Edit> edits;
    std::size_t deleted = 0, trimmed = 0;

    // Subsume existing file rules the new rule covers: drop the overlapping
    // permissions, removing a rule entirely once nothing is left. Restricted to
    // same decision/audit/owner and concrete existing paths so effective policy
    // is preserved (the new, broader rule still covers what is trimmed away).
    if (auto nr = parseSingleRule(rule); nr && nr->kind == RuleKind::File &&
                                         !nr->target.empty() &&
                                         !nr->perms.empty()) {
        for (const Rule& e : prof->rules) {
            if (e.kind != RuleKind::File || e.perms.empty())
                continue;
            if (e.decision != nr->decision || e.audit != nr->audit ||
                e.owner != nr->owner)
                continue;
            if (!isConcretePath(e.target) || !globMatch(nr->target, e.target))
                continue;
            const std::string reduced = subtractPerms(e.perms, nr->perms);
            if (reduced == e.perms)
                continue; // no overlapping permissions
            if (reduced.empty()) {
                auto [ds, de] = ruleLineRange(original, e);
                edits.push_back({ds, de, ""});
                ++deleted;
            } else if (auto [ps, pe] = locatePermsToken(original, e);
                       ps != std::string::npos) {
                edits.push_back({ps, pe, reduced});
                ++trimmed;
            }
        }
    }

    // Insert the new rule on its own line just before the profile's closing
    // brace (after all existing rules, so it never overlaps the edits above).
    const std::size_t brace = prof->bodyEndOffset;
    std::size_t lineStart = original.rfind('\n', brace);
    lineStart = (lineStart == std::string::npos) ? 0 : lineStart + 1;
    const std::string bracePrefix = original.substr(lineStart, brace - lineStart);
    if (isAllSpace(bracePrefix))
        edits.push_back({lineStart, lineStart, bracePrefix + "  " + rule + "\n"});
    else
        edits.push_back({brace, brace, rule + "\n  "});

    // Apply edits from the highest offset down so earlier offsets stay valid.
    std::sort(edits.begin(), edits.end(),
              [](const Edit& a, const Edit& b) { return a.start > b.start; });
    std::string content = original;
    std::size_t prevStart = std::string::npos;
    for (const Edit& ed : edits) {
        if (ed.end > prevStart)
            continue; // overlaps a higher edit (e.g. two rules on one line)
        content.replace(ed.start, ed.end - ed.start, ed.repl);
        prevStart = ed.start;
    }

    // Validate: the result parses and the rule count matches the delta.
    const std::size_t expected = prof->rules.size() + 1 - deleted;
    auto reparsed = parseText(content, file);
    const Profile* after = findProfile(reparsed, profileName);
    if (!after || after->rules.size() != expected) {
        res.message = "Internal check failed: edited profile did not parse as "
                      "expected; file left unchanged";
        return res;
    }

    if (!atomicReplace(file, content, res.message))
        return res;

    res.ok = true;
    res.message = "Added to " + file + ":\n    " + rule;
    if (trimmed)
        res.message += "\nTrimmed overlapping permissions from " +
                       std::to_string(trimmed) + " covered rule(s).";
    if (deleted)
        res.message += "\nRemoved " + std::to_string(deleted) +
                       " now-redundant rule(s).";
    return res;
}

namespace {
// Remove the leading `deny` qualifier from a rule's text, preserving any other
// leading qualifiers (audit/owner) and the rest. Returns the original string if
// no leading `deny` qualifier is present.
std::string stripDenyQualifier(const std::string& ruleText) {
    const std::size_t n = ruleText.size();
    std::size_t i = 0;
    while (i < n) {
        while (i < n && std::isspace(static_cast<unsigned char>(ruleText[i])))
            ++i;
        const std::size_t tokStart = i;
        while (i < n && !std::isspace(static_cast<unsigned char>(ruleText[i])))
            ++i;
        const std::string tok = ruleText.substr(tokStart, i - tokStart);
        if (tok == "deny") {
            std::size_t after = i;
            while (after < n &&
                   std::isspace(static_cast<unsigned char>(ruleText[after])))
                ++after;
            return ruleText.substr(0, tokStart) + ruleText.substr(after);
        }
        // Stop at the first non-qualifier token (the rule body).
        if (tok != "audit" && tok != "owner" && tok != "allow")
            break;
    }
    return ruleText;
}

std::size_t countDeny(const Profile& p) {
    std::size_t n = 0;
    for (const auto& r : p.rules)
        if (r.decision == Decision::Deny)
            ++n;
    return n;
}
} // namespace

EditResult reverseDenyRule(const std::string& file,
                           const std::string& profileName,
                           const std::string& denyRuleRaw) {
    EditResult res;
    res.rule = denyRuleRaw;

    bool ok = false;
    const std::string original = readFile(file, ok);
    if (!ok) {
        res.message = "Cannot read " + file;
        return res;
    }

    auto profiles = parseText(original, file);
    const Profile* prof = findProfile(profiles, profileName);
    if (!prof) {
        res.message = "Profile '" + profileName + "' not found in " + file;
        return res;
    }

    const Rule* deny = nullptr;
    for (const auto& r : prof->rules)
        if (r.decision == Decision::Deny && r.raw == denyRuleRaw) {
            deny = &r;
            break;
        }
    if (!deny) {
        res.message = "The deny rule was not found in the profile (it may have "
                      "already been changed):\n    " + denyRuleRaw;
        return res;
    }
    if (deny->endOffset <= deny->startOffset ||
        deny->endOffset > original.size()) {
        res.message = "Could not locate the deny rule's text in the file";
        return res;
    }

    const std::string ruleText =
        original.substr(deny->startOffset, deny->endOffset - deny->startOffset);
    const std::string reversed = stripDenyQualifier(ruleText);
    if (reversed == ruleText) {
        res.message = "Rule does not start with a 'deny' qualifier; nothing to "
                      "reverse";
        return res;
    }
    res.rule = reversed;

    const std::string content = original.substr(0, deny->startOffset) +
                                reversed +
                                original.substr(deny->endOffset);

    // Validate: still parses, same rule count, one fewer deny.
    const std::size_t oldRules = prof->rules.size();
    const std::size_t oldDeny = countDeny(*prof);
    auto reparsed = parseText(content, file);
    const Profile* after = findProfile(reparsed, profileName);
    if (!after || after->rules.size() != oldRules ||
        countDeny(*after) != oldDeny - 1) {
        res.message = "Internal check failed: reversed profile did not parse as "
                      "expected; file left unchanged";
        return res;
    }

    if (!atomicReplace(file, content, res.message))
        return res;

    res.ok = true;
    res.message = "Reversed deny rule in " + file +
                  ":\n    " + ruleText + "\n  ->\n    " + reversed;
    return res;
}

bool writeFileAtomically(const std::string& file, const std::string& content,
                         std::string& error) {
    return atomicReplace(file, content, error);
}

bool canReloadProfiles() {
    return ::geteuid() == 0;
}

ReloadResult reloadProfile(const std::string& file) {
    ReloadResult r;
    if (!canReloadProfiles()) {
        r.message = "Reapplying a profile requires root (uid 0).";
        return r;
    }

    int pipefd[2];
    if (::pipe(pipefd) != 0) {
        r.message = std::string("pipe() failed: ") + std::strerror(errno);
        return r;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        r.message = std::string("fork() failed: ") + std::strerror(errno);
        return r;
    }
    if (pid == 0) {
        // Child: send stdout+stderr to the pipe and exec apparmor_parser.
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::dup2(pipefd[1], STDERR_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        // execlp avoids any shell, so the path needs no quoting/escaping.
        ::execlp("apparmor_parser", "apparmor_parser", "-r", file.c_str(),
                 static_cast<char*>(nullptr));
        ::_exit(127); // exec failed
    }

    ::close(pipefd[1]);
    std::string out;
    char buf[4096];
    ssize_t n;
    while ((n = ::read(pipefd[0], buf, sizeof buf)) > 0)
        out.append(buf, static_cast<std::size_t>(n));
    ::close(pipefd[0]);

    int status = 0;
    ::waitpid(pid, &status, 0);
    const int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    if (code == 127) {
        r.message = "Could not run apparmor_parser (is it installed and on "
                    "PATH?).";
        return r;
    }
    if (code != 0) {
        r.message = "apparmor_parser -r failed (exit " + std::to_string(code) +
                    ")";
        if (!out.empty())
            r.message += ":\n" + out;
        return r;
    }

    r.ok = true;
    r.message = "Profile reapplied into the kernel (apparmor_parser -r).";
    if (!out.empty())
        r.message += "\n" + out;
    return r;
}

} // namespace apparmor
