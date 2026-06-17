#include "LogTailer.h"

#include <chrono>
#include <fstream>
#include <ios>

#include <sys/stat.h>

namespace {

constexpr std::size_t kBatchSize = 1000;
constexpr auto kPollInterval = std::chrono::milliseconds(250);

// File size via stat(); -1 on error. Used to detect rotation/truncation.
std::int64_t fileSize(const std::string& path) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0)
        return -1;
    return static_cast<std::int64_t>(st.st_size);
}

} // namespace

LogTailer::~LogTailer() {
    stop();
}

void LogTailer::setCallbacks(EventBatchFn onEvents, StatusFn onStatus) {
    m_onEvents = std::move(onEvents);
    m_onStatus = std::move(onStatus);
}

void LogTailer::stop() {
    if (m_thread.joinable()) {
        m_thread.request_stop();
        m_thread.join();
    }
}

void LogTailer::readAll(std::string path) {
    stop();
    m_thread = std::jthread(
        [this, path = std::move(path)](std::stop_token st) { worker(path, false, st); });
}

void LogTailer::startLive(std::string path) {
    stop();
    m_thread = std::jthread(
        [this, path = std::move(path)](std::stop_token st) { worker(path, true, st); });
}

void LogTailer::worker(const std::string& path, bool live, std::stop_token st) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        if (m_onStatus)
            m_onStatus("Error: cannot open " + path);
        return;
    }

    audit::EventGrouper grouper;
    std::vector<audit::Event> batch;
    bool firstDelivery = true;
    std::string pending; // incomplete trailing line carried between reads
    std::int64_t offset = 0;

    auto deliver = [&](bool force) {
        if (batch.size() < kBatchSize && !force)
            return;
        if (batch.empty() && !firstDelivery)
            return;
        if (m_onEvents)
            m_onEvents(std::move(batch), firstDelivery);
        batch.clear();
        firstDelivery = false;
    };

    auto consume = [&](std::string_view chunk) {
        pending.append(chunk);
        std::size_t start = 0;
        while (true) {
            std::size_t nl = pending.find('\n', start);
            if (nl == std::string::npos)
                break;
            std::string_view line(pending.data() + start, nl - start);
            if (auto rec = audit::parseLine(line))
                if (auto ev = grouper.add(std::move(*rec)))
                    batch.push_back(std::move(*ev));
            start = nl + 1;
        }
        pending.erase(0, start);
        deliver(false);
    };

    char buf[64 * 1024];
    bool reachedEofOnce = false;

    while (!st.stop_requested()) {
        in.read(buf, sizeof(buf));
        std::streamsize got = in.gcount();
        if (got > 0) {
            offset += got;
            consume(std::string_view(buf, static_cast<std::size_t>(got)));
        }

        if (in.eof()) {
            in.clear();
            // At EOF the current event is complete (its records were written
            // together), so flush it and push out whatever we have. In live
            // mode this runs every poll so freshly-appended events appear.
            if (auto ev = grouper.flush())
                batch.push_back(std::move(*ev));
            deliver(true);

            if (!reachedEofOnce) {
                reachedEofOnce = true;
                if (m_onStatus)
                    m_onStatus(live ? "Live: following " + path
                                    : "Loaded " + path);
                if (!live)
                    return;
            }

            // Live mode: wait, then look for appended data or rotation.
            std::int64_t size = fileSize(path);
            if (size >= 0 && size < offset) {
                // File was truncated/rotated — reopen from the top.
                if (m_onStatus)
                    m_onStatus("Log rotated — reloading " + path);
                in.close();
                in.open(path, std::ios::binary);
                if (!in) {
                    if (m_onStatus)
                        m_onStatus("Error reopening " + path);
                    return;
                }
                grouper = audit::EventGrouper{};
                pending.clear();
                offset = 0;
                firstDelivery = true;
                reachedEofOnce = false;
                continue;
            }

            // Sleep in small slices so stop requests are responsive.
            for (auto waited = std::chrono::milliseconds(0);
                 waited < kPollInterval && !st.stop_requested();
                 waited += std::chrono::milliseconds(50))
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
}
