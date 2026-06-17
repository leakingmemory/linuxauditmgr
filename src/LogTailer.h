#pragma once

#include <functional>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "AuditParser.h"

// Reads an audit log file on a background thread and delivers parsed,
// grouped events in batches. Two modes:
//   readAll()   — parse the whole file once, then finish.
//   startLive() — parse the whole file, then keep following appended data
//                 (handles log rotation/truncation by reopening).
//
// Callbacks are invoked FROM THE WORKER THREAD; the owner is responsible for
// marshalling them onto the UI thread.
class LogTailer {
public:
    // reset == true means "this is the first batch of a fresh read; clear the
    // existing view before appending".
    using EventBatchFn = std::function<void(std::vector<audit::Event>, bool reset)>;
    using StatusFn = std::function<void(const std::string&)>;

    LogTailer() = default;
    ~LogTailer();

    LogTailer(const LogTailer&) = delete;
    LogTailer& operator=(const LogTailer&) = delete;

    void setCallbacks(EventBatchFn onEvents, StatusFn onStatus);

    void readAll(std::string path);
    void startLive(std::string path);
    void stop();
    bool running() const { return m_thread.joinable(); }

private:
    void worker(const std::string& path, bool live, std::stop_token st);

    std::jthread m_thread;
    EventBatchFn m_onEvents;
    StatusFn     m_onStatus;
};
