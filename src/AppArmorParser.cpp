#include "AppArmorParser.h"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace apparmor {
namespace {

std::string trim(const std::string& s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};
    const auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

bool startsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), s.begin());
}

std::vector<std::string> splitWhitespace(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok)
        out.push_back(tok);
    return out;
}

// Blank out '#' comments with spaces, preserving every byte offset (and the
// "#include" directive). Keeping the length identical to the original text lets
// the parser record byte offsets that are valid against the file on disk.
std::string stripComments(const std::string& text) {
    std::string out = text;
    bool inComment = false;
    for (std::size_t i = 0; i < out.size(); ++i) {
        char c = out[i];
        if (c == '\n') {
            inComment = false;
            continue;
        }
        if (inComment) {
            out[i] = ' ';
            continue;
        }
        if (c == '#') {
            // "#include" is a directive, not a comment.
            if (out.compare(i, 8, "#include") == 0) {
                i += 7;
                continue;
            }
            inComment = true;
            out[i] = ' ';
        }
    }
    return out;
}

// Pull the <...> payload out of an include directive.
void addInclude(Profile& p, const std::string& stmt) {
    const auto lt = stmt.find('<');
    const auto gt = stmt.find('>', lt == std::string::npos ? 0 : lt);
    if (lt != std::string::npos && gt != std::string::npos && gt > lt)
        p.includes.push_back(stmt.substr(lt + 1, gt - lt - 1));
}

Profile parseHeader(const std::string& header, const std::string& sourceFile,
                    int line) {
    Profile p;
    p.sourceFile = sourceFile;
    p.startLine = line;

    auto tokens = splitWhitespace(header);
    std::size_t i = 0;
    if (i < tokens.size() && (tokens[i] == "profile" || tokens[i] == "hat"))
        ++i;

    // flags=(a,b) may appear anywhere after the name; pull it out first.
    for (std::size_t j = i; j < tokens.size();) {
        if (startsWith(tokens[j], "flags=")) {
            std::string inside = tokens[j].substr(6);
            inside.erase(std::remove(inside.begin(), inside.end(), '('),
                         inside.end());
            inside.erase(std::remove(inside.begin(), inside.end(), ')'),
                         inside.end());
            std::stringstream ss(inside);
            std::string f;
            while (std::getline(ss, f, ','))
                if (!trim(f).empty())
                    p.flags.push_back(trim(f));
            tokens.erase(tokens.begin() + j);
        } else {
            ++j;
        }
    }

    if (i < tokens.size())
        p.name = tokens[i++];
    if (i < tokens.size())
        p.attachment = tokens[i++];
    // Bare-path profile form ("/usr/bin/foo { … }"): the name *is* the path.
    else if (!p.name.empty() && (p.name[0] == '/' || startsWith(p.name, "@{")))
        p.attachment = p.name;

    return p;
}

void addRule(Profile& p, const std::string& text, int line,
             std::size_t startOffset, std::size_t endOffset) {
    Rule r;
    r.raw = text;
    r.line = line;
    r.startOffset = startOffset;
    r.endOffset = endOffset;

    auto tokens = splitWhitespace(text);
    std::size_t i = 0;
    // Leading qualifiers, in any order.
    for (; i < tokens.size(); ++i) {
        if (tokens[i] == "audit")
            r.audit = true;
        else if (tokens[i] == "deny")
            r.decision = Decision::Deny;
        else if (tokens[i] == "allow")
            r.decision = Decision::Allow;
        else if (tokens[i] == "owner")
            r.owner = true;
        else
            break;
    }
    if (i >= tokens.size())
        return; // nothing but qualifiers; skip

    const std::string& head = tokens[i];
    auto rest = [&](std::size_t from) {
        std::string s;
        for (std::size_t k = from; k < tokens.size(); ++k) {
            if (!s.empty())
                s += ' ';
            s += tokens[k];
        }
        return s;
    };

    if (head == "capability") {
        r.kind = RuleKind::Capability;
        r.target = rest(i + 1); // empty == all capabilities
    } else if (head == "network") {
        r.kind = RuleKind::Network;
        r.target = rest(i + 1);
    } else if (head == "signal") {
        r.kind = RuleKind::Signal;
        r.target = rest(i + 1);
    } else if (head == "ptrace") {
        r.kind = RuleKind::Ptrace;
        r.target = rest(i + 1);
    } else if (head == "dbus") {
        r.kind = RuleKind::Dbus;
        r.target = rest(i + 1);
    } else if (head == "unix") {
        r.kind = RuleKind::Unix;
        r.target = rest(i + 1);
    } else if (head == "mount" || head == "umount" || head == "remount" ||
               head == "pivot_root") {
        r.kind = RuleKind::Mount;
        r.target = rest(i);
    } else if (head == "change_profile") {
        r.kind = RuleKind::ChangeProfile;
        r.target = rest(i + 1);
    } else if (head == "link") {
        r.kind = RuleKind::Link;
        r.target = rest(i + 1);
    } else if (head == "set") {
        r.kind = RuleKind::Rlimit;
        r.target = rest(i + 1);
    } else if (head == "file") {
        r.kind = RuleKind::File;
        r.target = rest(i + 1); // bare "file," == all files
    } else if (head[0] == '/' || startsWith(head, "@{") || head[0] == '"') {
        // File rule: "<path> <perms> [-> target]".
        r.kind = RuleKind::File;
        r.target = head;
        if (i + 1 < tokens.size() && tokens[i + 1] != "->")
            r.perms = tokens[i + 1];
    } else {
        r.kind = RuleKind::Other;
        r.target = rest(i);
    }

    p.rules.push_back(std::move(r));
}

bool skipName(const std::string& name) {
    if (name.empty() || name[0] == '.')
        return true;
    static constexpr std::array kSkip = {"README", "Makefile"};
    for (const char* s : kSkip)
        if (name == s)
            return true;
    static constexpr std::array kSuffix = {".orig", ".dpkg-new", ".dpkg-old",
                                           ".dpkg-dist", ".rpmnew", ".rpmsave",
                                           "~"};
    for (const char* suf : kSuffix) {
        const std::string s(suf);
        if (name.size() >= s.size() &&
            std::equal(s.rbegin(), s.rend(), name.rbegin()))
            return true;
    }
    return false;
}

} // namespace

const char* ruleKindName(RuleKind kind) {
    switch (kind) {
    case RuleKind::File:          return "Files";
    case RuleKind::Capability:    return "Capabilities";
    case RuleKind::Network:       return "Network";
    case RuleKind::Signal:        return "Signal";
    case RuleKind::Ptrace:        return "Ptrace";
    case RuleKind::Dbus:          return "D-Bus";
    case RuleKind::Unix:          return "Unix sockets";
    case RuleKind::Mount:         return "Mount";
    case RuleKind::ChangeProfile: return "Change profile";
    case RuleKind::Link:          return "Link";
    case RuleKind::Rlimit:        return "Resource limits";
    case RuleKind::Other:         return "Other";
    }
    return "Other";
}

std::string describePerms(const std::string& perms) {
    std::vector<std::string> parts;
    for (std::size_t i = 0; i < perms.size(); ++i) {
        char c = perms[i];
        switch (c) {
        case 'r': parts.push_back("read"); break;
        case 'w': parts.push_back("write"); break;
        case 'a': parts.push_back("append"); break;
        case 'm': parts.push_back("mmap-exec"); break;
        case 'k': parts.push_back("lock"); break;
        case 'l': parts.push_back("link"); break;
        case 'C': parts.push_back("exec(child)"); break;
        case 'P': parts.push_back("exec(profile)"); break;
        case 'U': parts.push_back("exec(unconfined)"); break;
        case 'p': parts.push_back("exec(profile-inherit)"); break;
        case 'c': parts.push_back("exec(child-inherit)"); break;
        case 'u': parts.push_back("exec(unconfined-inherit)"); break;
        case 'i': // inherit-exec modifier; pairs with x
            parts.push_back("inherit-exec");
            break;
        case 'x': // bare x or the x in "ix": treat as exec
            if (i == 0 || perms[i - 1] != 'i')
                parts.push_back("exec");
            break;
        default: break;
        }
    }
    std::string out;
    for (const auto& p : parts) {
        if (!out.empty())
            out += ", ";
        out += p;
    }
    return out;
}

std::string normalizeFilePerms(const std::string& mask) {
    std::string out;
    auto add = [&](char c) {
        if (out.find(c) == std::string::npos)
            out.push_back(c);
    };
    bool sawWrite = false;
    for (char c : mask) {
        switch (c) {
        case 'r': add('r'); break;
        case 'w': add('w'); sawWrite = true; break;
        case 'c': add('w'); sawWrite = true; break; // create -> write
        case 'd': add('w'); sawWrite = true; break; // delete -> write
        case 'a': add('a'); break;
        case 'l': add('l'); break;
        case 'k': add('k'); break;
        case 'm': add('m'); break;
        case 'x': add('x'); break;
        default: break; // drop letters that are not rule permissions
        }
    }
    // A write rule already covers append, so drop a redundant 'a'.
    if (sawWrite)
        if (auto p = out.find('a'); p != std::string::npos)
            out.erase(p, 1);
    return out;
}

bool Profile::complain() const {
    return std::find(flags.begin(), flags.end(), "complain") != flags.end();
}

std::size_t Profile::allowCount() const {
    return static_cast<std::size_t>(std::count_if(
        rules.begin(), rules.end(),
        [](const Rule& r) { return r.decision == Decision::Allow; }));
}

std::size_t Profile::denyCount() const {
    return static_cast<std::size_t>(std::count_if(
        rules.begin(), rules.end(),
        [](const Rule& r) { return r.decision == Decision::Deny; }));
}

std::vector<Profile> parseText(const std::string& text,
                               const std::string& sourceFile) {
    const std::string clean = stripComments(text);

    std::vector<Profile> top;
    std::vector<Profile> stack; // stack.back() == currently open profile
    std::string buf;
    int line = 1;
    int bufStartLine = 1;
    std::size_t bufStartOffset = 0; // byte offset of the current statement
    // Path globs ("/{usr/,}bin") and variables ("@{PROC}") use braces and
    // commas *inside* a token. Track that depth so those characters are not
    // mistaken for profile blocks or rule terminators.
    int globDepth = 0;

    auto closeProfile = [&] {
        if (stack.empty())
            return;
        Profile done = std::move(stack.back());
        stack.pop_back();
        if (stack.empty())
            top.push_back(std::move(done));
        else
            stack.back().children.push_back(std::move(done));
    };

    for (std::size_t i = 0; i < clean.size(); ++i) {
        const char c = clean[i];
        if (c == '\n') {
            const std::string t = trim(buf);
            if (globDepth == 0 &&
                (startsWith(t, "include") || startsWith(t, "#include"))) {
                if (!stack.empty())
                    addInclude(stack.back(), t);
                buf.clear();
            } else if (t.empty()) {
                buf.clear();
            } else {
                buf.push_back(' '); // allow rules to span lines
            }
            ++line;
            continue;
        }
        if (c == '{') {
            // A brace that continues the current token (no preceding space) is
            // a glob/variable; a brace after whitespace opens a profile body.
            if (globDepth > 0 ||
                (!buf.empty() && buf.back() != ' ' && buf.back() != '\t')) {
                buf.push_back(c);
                ++globDepth;
            } else {
                stack.push_back(
                    parseHeader(trim(buf), sourceFile, bufStartLine));
                buf.clear();
            }
            continue;
        }
        if (c == '}') {
            if (globDepth > 0) {
                buf.push_back(c);
                --globDepth;
            } else {
                const std::string t = trim(buf);
                if (!t.empty() && !stack.empty())
                    addRule(stack.back(), t, bufStartLine, bufStartOffset, i);
                buf.clear();
                if (!stack.empty())
                    stack.back().bodyEndOffset = i;
                closeProfile();
            }
            continue;
        }
        if (c == ',') {
            if (globDepth > 0) {
                buf.push_back(c); // comma inside a glob alternation
                continue;
            }
            const std::string t = trim(buf);
            if (!t.empty() && !stack.empty())
                addRule(stack.back(), t, bufStartLine, bufStartOffset, i);
            buf.clear();
            continue;
        }
        if (buf.empty() && (c == ' ' || c == '\t'))
            continue; // drop leading whitespace
        if (buf.empty()) {
            bufStartLine = line;
            bufStartOffset = i;
        }
        buf.push_back(c);
    }

    // Unbalanced braces: salvage whatever is still open.
    while (!stack.empty())
        closeProfile();

    return top;
}

ParseResult parseDirectory(const std::string& dir) {
    ParseResult result;
    result.directory = dir;
    namespace fs = std::filesystem;

    std::error_code ec;
    fs::directory_iterator it(dir, ec), end;
    if (ec) {
        result.errors.push_back(dir + ": " + ec.message());
        return result;
    }

    for (; it != end; it.increment(ec)) {
        if (ec)
            break;
        const fs::directory_entry& entry = *it;
        std::error_code fec;
        if (!entry.is_regular_file(fec))
            continue; // skip abstractions/, tunables/, … subdirectories
        const std::string name = entry.path().filename().string();
        if (skipName(name))
            continue;

        std::ifstream in(entry.path());
        if (!in) {
            result.errors.push_back(name + ": cannot read (permission?)");
            continue;
        }
        std::ostringstream ss;
        ss << in.rdbuf();
        ++result.filesParsed;

        auto profiles = parseText(ss.str(), name);
        for (auto& p : profiles)
            result.profiles.push_back(std::move(p));
    }

    std::sort(result.profiles.begin(), result.profiles.end(),
              [](const Profile& a, const Profile& b) {
                  if (a.name != b.name)
                      return a.name < b.name;
                  return a.sourceFile < b.sourceFile;
              });
    std::sort(result.errors.begin(), result.errors.end());
    return result;
}

} // namespace apparmor
