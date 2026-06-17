#include "AuditParser.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <unordered_map>

namespace audit {

namespace {

constexpr char kGroupSep = '\x1d'; // separates raw from enriched fields

bool isHexDigit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

bool looksLikeHex(std::string_view v) {
    if (v.size() < 2 || (v.size() % 2) != 0)
        return false;
    return std::ranges::all_of(v, isHexDigit);
}

// Fields that audit may emit hex-encoded when they contain spaces or other
// "untrusted" characters. We decode these so the user sees real text.
// `recordType` matters: in SYSCALL records a0/a1/... are raw register values
// (must NOT be decoded), whereas in EXECVE records they are argv strings.
bool shouldHexDecode(std::string_view key, std::string_view recordType) {
    static constexpr std::string_view kKeys[] = {
        "proctitle", "exe", "cwd", "name", "path", "comm", "args", "data",
    };
    if (std::ranges::find(kKeys, key) != std::end(kKeys))
        return true;
    // EXECVE positional args: a0, a1, ... a23
    if (recordType == "EXECVE")
        return key.size() >= 2 && key[0] == 'a' &&
               std::ranges::all_of(key.substr(1), [](char c) { return std::isdigit(c); });
    return false;
}

std::string toLower(std::string_view s) {
    std::string out(s);
    std::ranges::transform(out, out.begin(), [](unsigned char c) { return std::tolower(c); });
    return out;
}

// Parse "key=value key=value ..." into fields. Values may be bare, "quoted",
// or hex-encoded. Enriched fields have their keys lowercased so that, e.g.,
// the resolved AUID="root" overlays the raw auid=0.
void parseFields(std::string_view body, bool enriched, std::string_view recordType,
                 std::vector<Field>& out) {
    std::size_t i = 0;
    const std::size_t n = body.size();
    while (i < n) {
        while (i < n && body[i] == ' ')
            ++i;
        if (i >= n)
            break;

        std::size_t keyStart = i;
        while (i < n && body[i] != '=' && body[i] != ' ')
            ++i;
        if (i >= n || body[i] != '=') {
            // Token without '=' (rare/garbage) — skip to next space.
            while (i < n && body[i] != ' ')
                ++i;
            continue;
        }
        std::string_view key = body.substr(keyStart, i - keyStart);
        ++i; // consume '='

        std::string value;
        if (i < n && body[i] == '"') {
            ++i;
            std::size_t vs = i;
            while (i < n && body[i] != '"')
                ++i;
            value.assign(body.substr(vs, i - vs));
            if (i < n)
                ++i; // closing quote
        } else {
            std::size_t vs = i;
            while (i < n && body[i] != ' ')
                ++i;
            std::string_view raw = body.substr(vs, i - vs);
            if (shouldHexDecode(key, recordType) && looksLikeHex(raw))
                value = decodeHexField(raw);
            else
                value.assign(raw);
        }

        out.push_back(Field{enriched ? toLower(key) : std::string(key),
                            std::move(value), enriched});
    }
}

} // namespace

std::string decodeHexField(std::string_view value) {
    if (!looksLikeHex(value))
        return std::string(value);
    std::string out;
    out.reserve(value.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    };
    for (std::size_t i = 0; i + 1 < value.size(); i += 2) {
        char ch = static_cast<char>((nib(value[i]) << 4) | nib(value[i + 1]));
        out.push_back(ch == '\0' ? ' ' : ch); // NUL separates argv entries
    }
    // Trim a trailing separator-space for tidiness.
    if (!out.empty() && out.back() == ' ')
        out.pop_back();
    return out;
}

std::optional<std::string_view> Record::get(std::string_view key) const {
    for (const auto& f : fields)
        if (!f.enriched && f.key == key)
            return std::string_view(f.value);
    for (const auto& f : fields)
        if (f.key == key)
            return std::string_view(f.value);
    return std::nullopt;
}

std::optional<std::string_view> Record::getResolved(std::string_view key) const {
    std::optional<std::string_view> rawHit;
    for (const auto& f : fields) {
        if (f.key != key)
            continue;
        if (f.enriched)
            return std::string_view(f.value);
        if (!rawHit)
            rawHit = std::string_view(f.value);
    }
    return rawHit;
}

std::optional<Record> parseLine(std::string_view line) {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
        line.remove_suffix(1);
    if (line.empty())
        return std::nullopt;

    constexpr std::string_view kType = "type=";
    if (!line.starts_with(kType))
        return std::nullopt;

    Record rec;
    rec.raw.assign(line);

    std::size_t pos = kType.size();
    std::size_t sp = line.find(' ', pos);
    if (sp == std::string_view::npos)
        return std::nullopt;
    rec.type.assign(line.substr(pos, sp - pos));

    // msg=audit(TS:SERIAL):
    std::size_t mp = line.find("audit(", sp);
    if (mp == std::string_view::npos)
        return std::nullopt;
    mp += std::strlen("audit(");
    std::size_t colon = line.find(':', mp);
    std::size_t close = line.find(')', mp);
    if (colon == std::string_view::npos || close == std::string_view::npos || colon > close)
        return std::nullopt;

    rec.timestamp = std::strtod(std::string(line.substr(mp, colon - mp)).c_str(), nullptr);
    rec.serial = std::strtoll(std::string(line.substr(colon + 1, close - colon - 1)).c_str(),
                              nullptr, 10);

    std::string_view body = line.substr(close + 1);
    if (body.starts_with(":"))
        body.remove_prefix(1);

    std::size_t gs = body.find(kGroupSep);
    if (gs == std::string_view::npos) {
        parseFields(body, /*enriched=*/false, rec.type, rec.fields);
    } else {
        parseFields(body.substr(0, gs), /*enriched=*/false, rec.type, rec.fields);
        parseFields(body.substr(gs + 1), /*enriched=*/true, rec.type, rec.fields);
    }
    return rec;
}

std::string_view syscallName(std::string_view /*archHex*/, std::string_view nr) {
    // Minimal x86_64 table covering the syscalls common in the sample log.
    static const std::unordered_map<std::string, std::string_view> kMap = {
        {"0", "read"}, {"1", "write"}, {"2", "open"}, {"3", "close"},
        {"4", "stat"}, {"5", "fstat"}, {"6", "lstat"}, {"9", "mmap"},
        {"10", "mprotect"}, {"11", "munmap"}, {"21", "access"},
        {"56", "clone"}, {"57", "fork"}, {"58", "vfork"}, {"59", "execve"},
        {"62", "kill"}, {"78", "getdents"}, {"80", "chdir"}, {"83", "mkdir"},
        {"82", "rename"}, {"84", "rmdir"}, {"87", "unlink"}, {"89", "readlink"},
        {"90", "chmod"}, {"92", "chown"}, {"101", "ptrace"}, {"137", "statfs"},
        {"217", "getdents64"}, {"257", "openat"}, {"262", "newfstatat"},
        {"280", "utimensat"}, {"321", "bpf"}, {"322", "execveat"},
    };
    auto it = kMap.find(std::string(nr));
    return it == kMap.end() ? std::string_view{} : it->second;
}

// ---- Event ---------------------------------------------------------------

namespace {

const Record* findRecord(const Event& ev, std::string_view type) {
    for (const auto& r : ev.records)
        if (r.type == type)
            return &r;
    return nullptr;
}

std::string strOr(std::optional<std::string_view> v, std::string_view dflt = "") {
    return v ? std::string(*v) : std::string(dflt);
}

} // namespace

std::string Event::typesJoined() const {
    std::string out;
    for (const auto& r : records) {
        if (!out.empty())
            out += ',';
        out += r.type;
    }
    return out;
}

std::string Event::pid() const {
    for (std::string_view t : {"SYSCALL", "AVC"}) {
        if (const Record* r = findRecord(*this, t))
            if (auto p = r->get("pid"))
                return std::string(*p);
    }
    for (const auto& r : records)
        if (auto p = r.get("pid"))
            return std::string(*p);
    return {};
}

std::string Event::comm() const {
    for (const auto& r : records)
        if (auto c = r.getResolved("comm"))
            return std::string(*c);
    return {};
}

std::string Event::exe() const {
    for (const auto& r : records)
        if (auto e = r.getResolved("exe"))
            return std::string(*e);
    // Fall back to the decoded proctitle / first EXECVE arg.
    if (const Record* p = findRecord(*this, "PROCTITLE"))
        if (auto pt = p->get("proctitle"))
            return std::string(*pt);
    return {};
}

std::string Event::summary() const {
    if (const Record* avc = findRecord(*this, "AVC")) {
        std::string s = strOr(avc->getResolved("apparmor"), "AVC");
        if (auto op = avc->get("operation"))
            s += " " + std::string(*op);
        std::string req = strOr(avc->get("requested_mask"));
        std::string den = strOr(avc->get("denied_mask"));
        if (!req.empty())
            s += " requested=" + req;
        if (!den.empty() && den != req)
            s += " denied=" + den;
        if (auto prof = avc->get("profile"))
            s += " profile=" + std::string(*prof);
        if (auto peer = avc->get("peer"))
            s += " peer=" + std::string(*peer);
        return s;
    }

    if (const Record* sc = findRecord(*this, "SYSCALL")) {
        std::string name = strOr(sc->getResolved("syscall"));
        if (name.empty() || std::ranges::all_of(name, [](char c){ return std::isdigit(c); }))
            if (auto sv = syscallName(strOr(sc->get("arch")), strOr(sc->get("syscall"))); !sv.empty())
                name = std::string(sv);
        std::string s = "syscall " + (name.empty() ? strOr(sc->get("syscall")) : name);
        if (auto ok = sc->get("success"))
            s += " success=" + std::string(*ok);
        if (auto ex = sc->get("exit"))
            s += " exit=" + std::string(*ex);
        if (std::string e = exe(); !e.empty())
            s += "  " + e;
        return s;
    }

    // Generic fallback: type plus a few interesting fields.
    if (!records.empty()) {
        const Record& r = records.front();
        std::string s = r.type;
        for (std::string_view k : {"res", "op", "operation", "acct", "exe", "comm"})
            if (auto v = r.getResolved(k))
                s += "  " + std::string(k) + "=" + std::string(*v);
        return s;
    }
    return {};
}

std::string Event::formattedTime() const {
    auto secs = static_cast<std::time_t>(timestamp);
    int ms = static_cast<int>((timestamp - static_cast<double>(secs)) * 1000.0 + 0.5);
    std::tm tmv{};
    localtime_r(&secs, &tmv);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    char out[40];
    std::snprintf(out, sizeof(out), "%s.%03d", buf, ms);
    return out;
}

std::string Event::detail() const {
    std::string out;
    out += "Event " + std::to_string(serial) + "   " + formattedTime() + "\n";
    out += "Summary: " + summary() + "\n";
    out += std::string(70, '-') + "\n";

    for (const auto& r : records) {
        out += "\n[" + r.type + "]\n";
        // Raw fields first, then resolved ones, grouped for readability.
        for (bool enriched : {false, true}) {
            bool printedHeader = false;
            for (const auto& f : r.fields) {
                if (f.enriched != enriched)
                    continue;
                if (enriched && !printedHeader) {
                    out += "  -- resolved --\n";
                    printedHeader = true;
                }
                out += "    " + f.key + " = " + f.value + "\n";
            }
        }
    }
    return out;
}

// ---- EventGrouper --------------------------------------------------------

std::optional<Event> EventGrouper::add(Record rec) {
    std::optional<Event> completed;
    if (m_have && (rec.serial != m_pending.serial || rec.timestamp != m_pending.timestamp)) {
        completed = std::move(m_pending);
        m_pending = Event{};
        m_have = false;
    }
    if (!m_have) {
        m_pending.serial = rec.serial;
        m_pending.timestamp = rec.timestamp;
        m_have = true;
    }
    m_pending.records.push_back(std::move(rec));
    return completed;
}

std::optional<Event> EventGrouper::flush() {
    if (!m_have)
        return std::nullopt;
    Event ev = std::move(m_pending);
    m_pending = Event{};
    m_have = false;
    return ev;
}

} // namespace audit
