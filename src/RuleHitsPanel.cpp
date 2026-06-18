#include "RuleHitsPanel.h"

#include <algorithm>
#include <cctype>
#include <ctime>

#include <wx/splitter.h>

namespace {
enum {
    ID_RhProfile = wxID_HIGHEST + 300,
    ID_RhSearch,
    ID_RhList,
};

constexpr int kColHits = 0;
constexpr int kColLast = 1;
constexpr int kColDecision = 2;
constexpr int kColKind = 3;
constexpr int kColRule = 4;

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

wxString formatTime(double epoch) {
    if (epoch <= 0.0)
        return "";
    std::time_t secs = static_cast<std::time_t>(epoch);
    std::tm tm{};
    localtime_r(&secs, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return wxString::FromUTF8(buf);
}

wxString profileLabel(const apparmor::Profile& p) {
    return wxString::FromUTF8(p.name.empty() ? p.attachment : p.name);
}
} // namespace

// Virtual list: one row per rule of the selected profile.
class RuleHitsPanel::RuleList : public wxListCtrl {
public:
    RuleList(RuleHitsPanel* owner, wxWindow* parent)
        : wxListCtrl(parent, ID_RhList, wxDefaultPosition, wxDefaultSize,
                     wxLC_REPORT | wxLC_VIRTUAL | wxLC_SINGLE_SEL),
          m_owner(owner) {}

protected:
    wxString OnGetItemText(long item, long column) const override {
        return m_owner->OnGetItemText(item, column);
    }

private:
    RuleHitsPanel* m_owner;
};

wxBEGIN_EVENT_TABLE(RuleHitsPanel, wxPanel)
    EVT_CHOICE(ID_RhProfile, RuleHitsPanel::onProfileChosen)
    EVT_TEXT(ID_RhSearch, RuleHitsPanel::onFilterChanged)
    EVT_LIST_ITEM_SELECTED(ID_RhList, RuleHitsPanel::onItemSelected)
wxEND_EVENT_TABLE()

RuleHitsPanel::RuleHitsPanel(wxWindow* parent, EventsProvider events,
                             ProfilesProvider profiles)
    : wxPanel(parent), m_events(std::move(events)),
      m_profiles(std::move(profiles)) {
    auto* sizer = new wxBoxSizer(wxVERTICAL);

    // --- Row 1: profile picker + filter ---
    auto* top = new wxBoxSizer(wxHORIZONTAL);
    top->Add(new wxStaticText(this, wxID_ANY, "Profile:"), 0,
             wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    m_profileChoice = new wxChoice(this, ID_RhProfile);
    top->Add(m_profileChoice, 2, wxALIGN_CENTER_VERTICAL | wxRIGHT, 16);
    top->Add(new wxStaticText(this, wxID_ANY, "Filter:"), 0,
             wxALIGN_CENTER_VERTICAL | wxRIGHT, 4);
    m_searchCtrl = new wxTextCtrl(this, ID_RhSearch, "", wxDefaultPosition,
                                  wxDefaultSize, wxTE_PROCESS_ENTER);
    m_searchCtrl->SetHint("rule text or kind...");
    top->Add(m_searchCtrl, 1, wxALIGN_CENTER_VERTICAL);
    sizer->Add(top, 0, wxEXPAND | wxALL, 8);

    // --- Row 2: summary line ---
    m_summary = new wxStaticText(this, wxID_ANY, "");
    sizer->Add(m_summary, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    // --- Splitter: rule list (top) + detail (bottom) ---
    auto* splitter = new wxSplitterWindow(this, wxID_ANY);
    splitter->SetMinimumPaneSize(100);

    m_list = new RuleList(this, splitter);
    m_list->AppendColumn("Hits", wxLIST_FORMAT_RIGHT, 70);
    m_list->AppendColumn("Last hit", wxLIST_FORMAT_LEFT, 160);
    m_list->AppendColumn("Decision", wxLIST_FORMAT_LEFT, 80);
    m_list->AppendColumn("Kind", wxLIST_FORMAT_LEFT, 110);
    m_list->AppendColumn("Rule", wxLIST_FORMAT_LEFT, 560);

    m_detail = new wxTextCtrl(splitter, wxID_ANY, "", wxDefaultPosition,
                              wxDefaultSize,
                              wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    m_detail->SetFont(wxFont(wxFontInfo(10).Family(wxFONTFAMILY_TELETYPE)));

    splitter->SplitHorizontally(m_list, m_detail, 360);
    sizer->Add(splitter, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    SetSizer(sizer);
}

void RuleHitsPanel::flattenInto(const apparmor::Profile& p, int depth) {
    wxString label = wxString(' ', depth * 2) +
                     (depth > 0 ? "> " : "") + profileLabel(p);
    m_profileChoice->Append(label);
    m_profileItems.push_back(&p);
    for (const auto& c : p.children)
        flattenInto(c, depth + 1);
}

void RuleHitsPanel::refresh() {
    // Split the audit log into AppArmor denial / allow records once.
    m_denials.clear();
    m_allows.clear();
    if (m_events) {
        for (const auto& ev : m_events()) {
            if (auto d = apparmor::denialFromEvent(ev))
                m_denials.push_back(std::move(*d));
            else if (auto a = apparmor::allowFromEvent(ev))
                m_allows.push_back(std::move(*a));
        }
    }

    // Repopulate the profile picker, preserving the current selection by name.
    const wxString prev = m_profileChoice->GetStringSelection();
    m_profileChoice->Clear();
    m_profileItems.clear();
    if (m_profiles)
        for (const auto& p : m_profiles().profiles)
            flattenInto(p, 0);

    if (m_profileChoice->IsEmpty()) {
        m_current = nullptr;
        m_hits.clear();
        m_filtered.clear();
        m_list->SetItemCount(0);
        m_list->Refresh();
        m_summary->SetLabel("No profiles loaded. Load a profiles directory in "
                            "the Profiles sub-tab.");
        m_detail->SetValue(wxString());
        return;
    }

    int sel = m_profileChoice->FindString(prev);
    m_profileChoice->SetSelection(sel == wxNOT_FOUND ? 0 : sel);
    recompute();
}

void RuleHitsPanel::recompute() {
    const int sel = m_profileChoice->GetSelection();
    m_current = (sel >= 0 && static_cast<std::size_t>(sel) < m_profileItems.size())
                    ? m_profileItems[sel]
                    : nullptr;

    if (m_current)
        m_hits = apparmor::countRuleHits(*m_current, m_denials, m_allows);
    else
        m_hits.clear();

    // Summary: how many rules, how many were hit, total events attributed.
    std::size_t hitRules = 0, total = 0;
    for (const auto& h : m_hits) {
        if (h.count > 0)
            ++hitRules;
        total += h.count;
    }
    if (m_current) {
        m_summary->SetLabel(wxString::Format(
            "%s: %zu rules, %zu hit by the log (%zu events matched), %zu never "
            "hit. %zu denials / %zu allows in the log.",
            profileLabel(*m_current), m_hits.size(), hitRules, total,
            m_hits.size() - hitRules, m_denials.size(), m_allows.size()));
    }
    m_summary->Wrap(GetClientSize().GetWidth() - 24);
    Layout();

    rebuildFilter();
    m_detail->SetValue(
        m_hits.empty()
            ? wxString("This profile has no rules of its own (it may rely "
                       "entirely on included abstractions).")
            : wxString("Select a rule to see its details and hit timing."));
}

bool RuleHitsPanel::matchesFilter(std::size_t ruleIdx) const {
    const wxString raw = m_searchCtrl ? m_searchCtrl->GetValue() : wxString();
    if (raw.empty())
        return true;
    if (!m_current || ruleIdx >= m_current->rules.size())
        return false;
    const std::string needle = toLower(raw.ToStdString());
    const apparmor::Rule& r = m_current->rules[ruleIdx];
    if (toLower(r.raw).find(needle) != std::string::npos)
        return true;
    if (toLower(apparmor::ruleKindName(r.kind)).find(needle) != std::string::npos)
        return true;
    return false;
}

void RuleHitsPanel::rebuildFilter() {
    m_filtered.clear();
    if (m_current)
        for (std::size_t i = 0; i < m_current->rules.size(); ++i)
            if (matchesFilter(i))
                m_filtered.push_back(i);

    // Most-hit rules first; ties keep the original rule order (stable).
    std::stable_sort(m_filtered.begin(), m_filtered.end(),
                     [this](std::size_t a, std::size_t b) {
                         return m_hits[a].count > m_hits[b].count;
                     });

    m_list->SetItemCount(static_cast<long>(m_filtered.size()));
    m_list->Refresh();
}

void RuleHitsPanel::onProfileChosen(wxCommandEvent&) {
    recompute();
}

void RuleHitsPanel::onFilterChanged(wxCommandEvent&) {
    rebuildFilter();
}

void RuleHitsPanel::onItemSelected(wxListEvent& evt) {
    long row = evt.GetIndex();
    if (row < 0 || static_cast<std::size_t>(row) >= m_filtered.size())
        return;
    m_detail->SetValue(detailFor(m_filtered[row]));
}

wxString RuleHitsPanel::OnGetItemText(long item, long column) const {
    if (item < 0 || static_cast<std::size_t>(item) >= m_filtered.size())
        return {};
    const std::size_t idx = m_filtered[item];
    const apparmor::Rule& r = m_current->rules[idx];
    const apparmor::RuleHitCount& h = m_hits[idx];
    switch (column) {
    case kColHits:     return wxString::Format("%zu", h.count);
    case kColLast:     return formatTime(h.lastSeen);
    case kColDecision: return r.decision == apparmor::Decision::Deny ? "deny"
                                                                     : "allow";
    case kColKind:     return apparmor::ruleKindName(r.kind);
    case kColRule:     return wxString::FromUTF8(r.raw);
    default:           return {};
    }
}

wxString RuleHitsPanel::detailFor(std::size_t ruleIdx) const {
    if (!m_current || ruleIdx >= m_current->rules.size())
        return {};
    const apparmor::Rule& r = m_current->rules[ruleIdx];
    const apparmor::RuleHitCount& h = m_hits[ruleIdx];

    wxString out;
    auto line = [&](const wxString& s) { out += s + "\n"; };

    line("Rule:        " + wxString::FromUTF8(r.raw));
    line(wxString("Decision:    ") +
         (r.decision == apparmor::Decision::Deny ? "deny" : "allow"));
    line(wxString("Kind:        ") + apparmor::ruleKindName(r.kind));
    if (r.owner)
        line("Owner-only:  yes (matches only files owned by the running user)");
    if (r.audit)
        line("Audited:     yes (matching accesses are logged)");
    if (r.kind == apparmor::RuleKind::File && !r.perms.empty()) {
        const std::string desc = apparmor::describePerms(r.perms);
        line("Permissions: " + wxString::FromUTF8(r.perms) +
             (desc.empty() ? wxString()
                           : "   [" + wxString::FromUTF8(desc) + "]"));
    }

    line("");
    line(wxString::Format("Hits:        %zu event(s) in the loaded log",
                          h.count));
    if (h.count > 0) {
        line("First hit:   " + formatTime(h.firstSeen));
        line("Last hit:    " + formatTime(h.lastSeen));
    } else {
        line("This rule was not exercised by any event in the loaded log.");
    }

    if (r.decision == apparmor::Decision::Allow)
        line("\nAllow rules are credited for ALLOWED records (logged in "
             "complain mode or by an `audit` rule); an enforcing allow that is "
             "never logged will show 0.");
    else
        line("\nDeny rules are credited for the DENIED records they explain.");

    return out;
}
