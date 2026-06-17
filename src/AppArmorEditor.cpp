#include "AppArmorEditor.h"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

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

} // namespace

std::optional<std::string> buildRule(const Denial& d, Decision decision) {
    const std::string prefix = (decision == Decision::Deny) ? "deny " : "";
    const std::string mask = !d.deniedMask.empty() ? d.deniedMask
                                                   : d.requestedMask;

    switch (kindForDenial(d)) {
    case RuleKind::File: {
        if (d.target.empty() || mask.empty())
            return std::nullopt;
        return prefix + maybeQuote(d.target) + ' ' + mask + ',';
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
    const std::size_t oldRuleCount = prof->rules.size();

    // Insert the rule on its own line just before the profile's closing brace.
    const std::size_t brace = prof->bodyEndOffset;
    std::size_t lineStart = original.rfind('\n', brace);
    lineStart = (lineStart == std::string::npos) ? 0 : lineStart + 1;
    const std::string bracePrefix = original.substr(lineStart, brace - lineStart);

    std::string content;
    if (isAllSpace(bracePrefix)) {
        const std::string indent = bracePrefix + "  ";
        content = original.substr(0, lineStart) + indent + rule + '\n' +
                  original.substr(lineStart);
    } else {
        // Closing brace shares its line with other text; fall back to inserting
        // right before it.
        content = original.substr(0, brace) + rule + "\n  " +
                  original.substr(brace);
    }

    // Validate: the edited text must still parse and the profile must have
    // gained exactly the one rule.
    auto reparsed = parseText(content, file);
    const Profile* after = findProfile(reparsed, profileName);
    if (!after || after->rules.size() != oldRuleCount + 1) {
        res.message = "Internal check failed: edited profile did not parse as "
                      "expected; file left unchanged";
        return res;
    }

    // --- Crash-safe write: temp file -> fsync -> verify -> atomic rename. ---
    namespace fs = std::filesystem;
    const fs::path target(file);
    const fs::path tmp =
        target.parent_path() /
        (target.filename().string() + ".aatmp." + std::to_string(::getpid()));

    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        res.message = "Cannot create temp file " + tmp.string() + ": " +
                      std::strerror(errno);
        return res;
    }

    auto fail = [&](const std::string& msg) {
        ::close(fd);
        ::unlink(tmp.c_str());
        res.message = msg;
        return res;
    };

    std::size_t written = 0;
    while (written < content.size()) {
        ssize_t n = ::write(fd, content.data() + written,
                            content.size() - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return fail(std::string("write failed: ") + std::strerror(errno));
        }
        written += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0)
        return fail(std::string("fsync failed: ") + std::strerror(errno));

    // Preserve the original file's permissions on the replacement.
    struct stat st{};
    if (::stat(file.c_str(), &st) == 0)
        ::fchmod(fd, st.st_mode & 0777);
    ::close(fd);

    // Verify the bytes on disk before replacing anything.
    bool vok = false;
    const std::string back = readFile(tmp.string(), vok);
    if (!vok || back != content) {
        ::unlink(tmp.c_str());
        res.message = "Verification of the temp file failed; file left "
                      "unchanged";
        return res;
    }

    if (::rename(tmp.c_str(), file.c_str()) != 0) {
        std::string msg = std::string("rename failed: ") + std::strerror(errno);
        ::unlink(tmp.c_str());
        res.message = msg;
        return res;
    }

    // Persist the directory entry so the rename survives a crash.
    if (int dfd = ::open(target.parent_path().c_str(), O_RDONLY | O_DIRECTORY);
        dfd >= 0) {
        ::fsync(dfd);
        ::close(dfd);
    }

    res.ok = true;
    res.message = "Added to " + target.filename().string() + ":\n    " + rule;
    return res;
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
