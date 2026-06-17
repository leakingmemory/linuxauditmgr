#include <catch2/catch_all.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>
#include <vector>

#include "LogTailer.h"
#include "fixtures.h"

namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {

// A temp file that cleans itself up.
struct TempLog {
    fs::path path = fs::temp_directory_path() /
                    ("auditmgr_test_" + std::to_string(::getpid()) + "_" +
                     std::to_string(reinterpret_cast<std::uintptr_t>(&path)) + ".log");
    ~TempLog() { std::error_code ec; fs::remove(path, ec); }

    void write(std::string_view content, bool append) {
        std::ofstream f(path, append ? std::ios::app : std::ios::trunc);
        f << content;
    }
};

// Thread-safe sink that records delivered events and reset signals.
struct Sink {
    std::mutex m;
    std::atomic<int> total{0};
    std::atomic<int> resets{0};
    std::vector<audit::Event> events;
    std::atomic<bool> reachedEof{false};

    void install(LogTailer& t) {
        t.setCallbacks(
            [this](std::vector<audit::Event> evs, bool reset) {
                std::scoped_lock lk(m);
                if (reset) { resets++; events.clear(); }
                total += static_cast<int>(evs.size());
                for (auto& e : evs) events.push_back(std::move(e));
            },
            [this](const std::string& s) {
                if (s.rfind("Loaded", 0) == 0 || s.rfind("Live:", 0) == 0)
                    reachedEof = true;
            });
    }
};

// Poll until pred() or timeout; returns whether pred() became true.
template <class Pred>
bool waitFor(Pred pred, std::chrono::milliseconds timeout = 3000ms) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(10ms);
    }
    return pred();
}

std::string fourRecords() {
    return std::string(fixtures::kAvc) + "\n" + std::string(fixtures::kSyscall) +
           "\n" + std::string(fixtures::kProctitle) + "\n" +
           std::string(fixtures::kExecve) + "\n";
}

} // namespace

TEST_CASE("LogTailer.readAll parses the whole file then stops") {
    TempLog log;
    log.write(fourRecords(), /*append=*/false);

    Sink sink;
    LogTailer tailer;
    sink.install(tailer);
    tailer.readAll(log.path.string());

    REQUIRE(waitFor([&] { return sink.reachedEof.load(); }));
    REQUIRE(waitFor([&] { return sink.total.load() == 2; }));

    tailer.stop();
    CHECK(sink.total == 2);          // two distinct serials (1001, 1002)
    CHECK(sink.resets == 1);         // one reset at the start of the read
    CHECK_FALSE(tailer.running());
}

TEST_CASE("LogTailer.readAll on a missing file reports an error, no events") {
    Sink sink;
    LogTailer tailer;
    std::atomic<bool> gotError{false};
    tailer.setCallbacks(
        [&](std::vector<audit::Event>, bool) { sink.total++; },
        [&](const std::string& s) { if (s.rfind("Error", 0) == 0) gotError = true; });
    tailer.readAll("/no/such/audit.log");

    REQUIRE(waitFor([&] { return gotError.load(); }));
    CHECK(sink.total == 0);
}

TEST_CASE("LogTailer.startLive picks up appended events") {
    TempLog log;
    log.write(std::string(fixtures::kDaemonStart) + "\n", /*append=*/false);

    Sink sink;
    LogTailer tailer;
    sink.install(tailer);
    tailer.startLive(log.path.string());

    // Initial content (1 event) is delivered.
    REQUIRE(waitFor([&] { return sink.total.load() == 1; }));

    // Append a second event; the tailer should notice it while following.
    log.write(std::string(fixtures::kLogin) + "\n", /*append=*/true);
    REQUIRE(waitFor([&] { return sink.total.load() == 2; }));

    tailer.stop();
    CHECK(sink.total == 2);
}

TEST_CASE("LogTailer.startLive reloads after rotation/truncation") {
    TempLog log;
    log.write(std::string(fixtures::kDaemonStart) + "\n", /*append=*/false);

    Sink sink;
    LogTailer tailer;
    sink.install(tailer);
    tailer.startLive(log.path.string());
    REQUIRE(waitFor([&] { return sink.total.load() == 1; }));

    // Truncate and write fresh, smaller content — simulates logrotate.
    log.write(std::string(fixtures::kExecve) + "\n", /*append=*/false);

    // A reset is emitted (view cleared) and the new event delivered.
    REQUIRE(waitFor([&] { return sink.resets.load() >= 2; }));
    REQUIRE(waitFor([&] {
        std::scoped_lock lk(sink.m);
        return sink.events.size() == 1 && sink.events.front().serial == 1002;
    }));

    tailer.stop();
}
