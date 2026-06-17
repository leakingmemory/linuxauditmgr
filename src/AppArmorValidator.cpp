#include "AppArmorValidator.h"

#include <cstdlib>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace apparmor {
namespace {

// Run a command, capturing combined stdout/stderr. Returns the exit code, or
// 127 if the program could not be executed.
int runCapture(const std::vector<std::string>& argv, std::string& output) {
    int pipefd[2];
    if (::pipe(pipefd) != 0)
        return 127;

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        return 127;
    }
    if (pid == 0) {
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::dup2(pipefd[1], STDERR_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        std::vector<char*> args;
        args.reserve(argv.size() + 1);
        for (const auto& a : argv)
            args.push_back(const_cast<char*>(a.c_str()));
        args.push_back(nullptr);
        ::execvp(args[0], args.data());
        ::_exit(127);
    }

    ::close(pipefd[1]);
    char buf[4096];
    ssize_t n;
    while ((n = ::read(pipefd[0], buf, sizeof buf)) > 0)
        output.append(buf, static_cast<std::size_t>(n));
    ::close(pipefd[0]);

    int status = 0;
    ::waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

bool isExecutable(const std::string& path) {
    return ::access(path.c_str(), X_OK) == 0;
}

} // namespace

bool validatorAvailable() {
    if (const char* path = std::getenv("PATH")) {
        std::string p(path);
        std::size_t start = 0;
        while (start <= p.size()) {
            const std::size_t end = p.find(':', start);
            const std::string dir =
                p.substr(start, end == std::string::npos ? std::string::npos
                                                         : end - start);
            if (!dir.empty() && isExecutable(dir + "/apparmor_parser"))
                return true;
            if (end == std::string::npos)
                break;
            start = end + 1;
        }
    }
    for (const char* dir : {"/usr/sbin", "/sbin", "/usr/bin", "/bin"})
        if (isExecutable(std::string(dir) + "/apparmor_parser"))
            return true;
    return false;
}

ValidationResult validateProfile(const std::string& fullPath) {
    ValidationResult r;
    r.file = fullPath;

    std::string output;
    const int code = runCapture(
        {"apparmor_parser", "-Q", "--skip-cache", fullPath}, output);

    if (code == 127) {
        r.ok = false;
        r.output = "Could not run apparmor_parser (is it installed?)";
        return r;
    }
    r.ok = (code == 0);
    if (!r.ok) {
        r.output = output.empty()
                       ? ("apparmor_parser exited with code " +
                          std::to_string(code))
                       : output;
    }
    return r;
}

} // namespace apparmor
