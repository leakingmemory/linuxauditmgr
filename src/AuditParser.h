#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Model + parser for Linux audit (auditd) log lines.
//
// A physical log line is a single "record":
//     type=AVC msg=audit(1781382071.765:223351): field=val field=val ...
//
// Records that share the same (timestamp, serial) belong to one logical
// "event" (e.g. an AVC denial plus its SYSCALL, PROCTITLE, EXECVE records).
//
// Logs written in ENRICHED format append already-resolved fields after a
// 0x1d (GS) byte, e.g.  key=(null)\x1dARCH=x86_64 SYSCALL=read AUID="root".
// We parse those too and use them to produce human-readable output.

namespace audit {

struct Field {
    std::string key;
    std::string value;       // value as written (unquoted, hex-decoded where useful)
    bool        enriched{};  // true if it came from the resolved (post-0x1d) section
};

class Record {
public:
    std::string              type;       // e.g. "AVC", "SYSCALL"
    std::int64_t             serial = 0;  // event serial within audit()
    double                   timestamp = 0.0;  // epoch seconds (with ms fraction)
    std::vector<Field>       fields;
    std::string              raw;        // original line (without trailing newline)

    // Returns the value of the first field with the given key, preferring the
    // raw value over the enriched one. Empty optional if absent.
    std::optional<std::string_view> get(std::string_view key) const;
    // Prefers the enriched (resolved) value when present, else the raw value.
    std::optional<std::string_view> getResolved(std::string_view key) const;
};

class Event {
public:
    std::int64_t             serial = 0;
    double                   timestamp = 0.0;
    std::vector<Record>      records;

    // Convenience accessors derived from the contained records.
    std::string typesJoined() const;       // "AVC,SYSCALL,PROCTITLE"
    std::string pid() const;
    std::string comm() const;
    std::string exe() const;
    std::string summary() const;           // one-line human description
    std::string formattedTime() const;     // "2026-06-17 11:01:11.765"

    // Full multi-line human-readable dump for the detail pane.
    std::string detail() const;
};

// Parse a single log line into a Record. Returns nullopt for blank lines or
// lines that do not look like audit records.
std::optional<Record> parseLine(std::string_view line);

// Decode an audit hex-encoded field (e.g. proctitle) into text. Embedded NUL
// bytes are turned into spaces (they separate argv entries). If the input is
// not valid even-length hex it is returned unchanged.
std::string decodeHexField(std::string_view value);

// Map an x86_64 syscall number to its name, or "" if unknown.
std::string_view syscallName(std::string_view archHex, std::string_view nr);

// Groups a flat stream of records into events. Records for one event are
// contiguous in the log, so this just flushes whenever (serial,timestamp)
// changes. Feed records with add(); collect completed events; call flush()
// at end-of-input to emit the final pending event.
class EventGrouper {
public:
    // Adds a record; if it starts a new event, the previous (now complete)
    // event is returned.
    std::optional<Event> add(Record rec);
    // Returns and clears any pending event (call at EOF).
    std::optional<Event> flush();

private:
    Event m_pending;
    bool  m_have = false;
};

} // namespace audit
