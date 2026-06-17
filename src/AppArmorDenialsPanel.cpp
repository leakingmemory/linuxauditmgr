#include "AppArmorDenialsPanel.h"

#include <algorithm>
#include <cctype>
#include <ctime>

#include <wx/splitter.h>

namespace {
enum {
    ID_DenSearch = wxID_HIGHEST + 200,
    ID_DenReload,
    ID_DenList,
};

constexpr int kColProfile = 0;
constexpr int kColOp = 1;
constexpr int kColTarget = 2;
constexpr int kColDenied = 3;
constexpr int kColCount = 4;
constexpr int kColKind = 5;
constexpr int kColLast = 6;

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
} // namespace

class AppArmorDenialsPanel::DenialList : public wxListCtrl {
public:
    DenialList(AppArmorDenialsPanel* owner, wxWindow* parent)
        : wxListCtrl(parent, ID_DenList, wxDefaultPosition, wxDefaultSize,
                     wxLC_REPORT | wxLC_VIRTUAL | wxLC_SINGLE_SEL),
          m_owner(owner) {}

protected:
    wxString OnGetItemText(long item, long column) const override {
        return m_owner->OnGetItemText(item, column);
    }

private:
    AppArmorDenialsPanel* m_owner;
};

wxBEGIN_EVENT_TABLE(AppArmorDenialsPanel, wxPanel)
    EVT_BUTTON(ID_DenReload, AppArmorDenialsPanel::onRefresh)
    EVT_TEXT(ID_DenSearch, AppArmorDenialsPanel::onFilterChanged)
    EVT_LIST_ITEM_SELECTED(ID_DenList, AppArmorDenialsPanel::onItemSelected)
wxEND_EVENT_TABLE()

AppArmorDenialsPanel::AppArmorDenialsPanel(wxWindow* parent,
                                           EventsProvider events,
                                           ProfilesProvider profiles)
    : wxPanel(parent), m_events(std::move(events)),
      m_profiles(std::move(profiles)) {
    auto* sizer = new wxBoxSizer(wxVERTICAL);

    // --- Row 1: explanation + refresh ---
    auto* topRow = new wxBoxSizer(wxHORIZONTAL);
    m_summary = new wxStaticText(
        this, wxID_ANY,
        "AppArmor denials from the loaded audit log. Load a log in the Audit "
        "Log tab, then Refresh.");
    topRow->Add(m_summary, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);
    topRow->Add(new wxButton(this, ID_DenReload, "Refresh"), 0);
    sizer->Add(topRow, 0, wxEXPAND | wxALL, 8);

    // --- Row 2: filter ---
    auto* filterRow = new wxBoxSizer(wxHORIZONTAL);
    filterRow->Add(new wxStaticText(this, wxID_ANY, "Filter:"), 0,
                   wxALIGN_CENTER_VERTICAL | wxRIGHT, 4);
    m_searchCtrl = new wxTextCtrl(this, ID_DenSearch, "", wxDefaultPosition,
                                  wxDefaultSize, wxTE_PROCESS_ENTER);
    m_searchCtrl->SetHint("profile, operation, path…");
    filterRow->Add(m_searchCtrl, 1, wxALIGN_CENTER_VERTICAL);
    sizer->Add(filterRow, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    // --- Splitter: denial list (top) + detail (bottom) ---
    auto* splitter = new wxSplitterWindow(this, wxID_ANY);
    splitter->SetMinimumPaneSize(120);

    m_list = new DenialList(this, splitter);
    m_list->AppendColumn("Profile", wxLIST_FORMAT_LEFT, 300);
    m_list->AppendColumn("Operation", wxLIST_FORMAT_LEFT, 90);
    m_list->AppendColumn("Denied target", wxLIST_FORMAT_LEFT, 300);
    m_list->AppendColumn("Mask", wxLIST_FORMAT_LEFT, 60);
    m_list->AppendColumn("Count", wxLIST_FORMAT_RIGHT, 70);
    m_list->AppendColumn("Kind of denial", wxLIST_FORMAT_LEFT, 130);
    m_list->AppendColumn("Last seen", wxLIST_FORMAT_LEFT, 160);

    m_detail = new wxTextCtrl(splitter, wxID_ANY, "", wxDefaultPosition,
                              wxDefaultSize,
                              wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    m_detail->SetFont(wxFont(wxFontInfo(10).Family(wxFONTFAMILY_TELETYPE)));

    splitter->SplitHorizontally(m_list, m_detail, 320);
    sizer->Add(splitter, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    SetSizer(sizer);
}

void AppArmorDenialsPanel::refresh() {
    std::vector<apparmor::Denial> denials;
    if (m_events) {
        for (const auto& ev : m_events())
            if (auto d = apparmor::denialFromEvent(ev))
                denials.push_back(std::move(*d));
    }

    m_groups = apparmor::aggregateDenials(denials);
    if (m_profiles)
        apparmor::correlate(m_groups, m_profiles());

    std::size_t explicitDeny = 0, implicit = 0, unknown = 0;
    for (const auto& g : m_groups) {
        switch (g.correlation) {
        case apparmor::Correlation::ExplicitDeny: ++explicitDeny; break;
        case apparmor::Correlation::Implicit:     ++implicit; break;
        case apparmor::Correlation::Unknown:      ++unknown; break;
        }
    }

    if (m_groups.empty()) {
        m_summary->SetLabel(
            "No AppArmor denials in the loaded audit log. Load a log in the "
            "Audit Log tab, then Refresh.");
    } else {
        m_summary->SetLabel(wxString::Format(
            "%zu distinct denials  -  %zu explicit deny rule, %zu implicit, "
            "%zu profile not loaded",
            m_groups.size(), explicitDeny, implicit, unknown));
    }
    m_summary->Wrap(GetClientSize().GetWidth() - 120);
    Layout();

    rebuildFilter();
    m_detail->SetValue(m_groups.empty()
                           ? wxString()
                           : "Select a denial to see details and the matching "
                             "rule (if any).");
}

bool AppArmorDenialsPanel::matches(const apparmor::DenialGroup& g) const {
    const wxString raw = m_searchCtrl ? m_searchCtrl->GetValue() : wxString();
    if (raw.empty())
        return true;
    const std::string needle = toLower(raw.ToStdString());
    const apparmor::Denial& d = g.sample;
    return toLower(d.profile).find(needle) != std::string::npos ||
           toLower(d.operation).find(needle) != std::string::npos ||
           toLower(d.target).find(needle) != std::string::npos ||
           toLower(d.comm).find(needle) != std::string::npos;
}

void AppArmorDenialsPanel::rebuildFilter() {
    m_filtered.clear();
    for (std::size_t i = 0; i < m_groups.size(); ++i)
        if (matches(m_groups[i]))
            m_filtered.push_back(i);
    m_list->SetItemCount(static_cast<long>(m_filtered.size()));
    m_list->Refresh();
}

void AppArmorDenialsPanel::onRefresh(wxCommandEvent&) {
    refresh();
}

void AppArmorDenialsPanel::onFilterChanged(wxCommandEvent&) {
    rebuildFilter();
}

void AppArmorDenialsPanel::onItemSelected(wxListEvent& evt) {
    long row = evt.GetIndex();
    if (row < 0 || static_cast<std::size_t>(row) >= m_filtered.size())
        return;
    m_detail->SetValue(detailFor(m_groups[m_filtered[row]]));
}

wxString AppArmorDenialsPanel::OnGetItemText(long item, long column) const {
    if (item < 0 || static_cast<std::size_t>(item) >= m_filtered.size())
        return {};
    const apparmor::DenialGroup& g = m_groups[m_filtered[item]];
    const apparmor::Denial& d = g.sample;
    switch (column) {
    case kColProfile: return wxString::FromUTF8(d.profile);
    case kColOp:      return wxString::FromUTF8(d.operation);
    case kColTarget:  return wxString::FromUTF8(d.target);
    case kColDenied:  return wxString::FromUTF8(d.deniedMask);
    case kColCount:   return wxString::Format("%zu", g.count);
    case kColKind:    return apparmor::correlationName(g.correlation);
    case kColLast:    return formatTime(g.lastSeen);
    default:          return {};
    }
}

wxString AppArmorDenialsPanel::detailFor(const apparmor::DenialGroup& g) const {
    const apparmor::Denial& d = g.sample;
    wxString out;
    auto line = [&](const wxString& s) { out += s + "\n"; };

    line("Profile:     " + wxString::FromUTF8(d.profile));
    line("Operation:   " + wxString::FromUTF8(d.operation) +
         (d.klass.empty() ? wxString()
                          : "   (class " + wxString::FromUTF8(d.klass) + ")"));
    line("Denied:      " + wxString::FromUTF8(d.target));
    line("Mask:        requested=" + wxString::FromUTF8(d.requestedMask) +
         "  denied=" + wxString::FromUTF8(d.deniedMask));
    line("Process:     " + wxString::FromUTF8(d.comm) + "  (pid " +
         wxString::FromUTF8(d.pid) + ")");
    line(wxString::Format("Occurrences: %zu", g.count));
    line("First seen:  " + formatTime(g.firstSeen));
    line("Last seen:   " + formatTime(g.lastSeen));
    line("");

    switch (g.correlation) {
    case apparmor::Correlation::ExplicitDeny:
        line("This matches an explicit deny rule in the profile:");
        line("    " + wxString::FromUTF8(g.matchedRule));
        line("");
        line("(A plain `deny` rule is normally silent; this denial is logged, "
             "so the rule was written as `audit deny`.)");
        break;
    case apparmor::Correlation::Implicit:
        line("No explicit deny rule matches — this is an implicit denial: the "
             "profile simply does not allow this access.");
        line("");
        line("To permit it, add an allow rule to the profile; to silence it "
             "without allowing, add a `deny` rule.");
        break;
    case apparmor::Correlation::Unknown:
        line("The denied profile is not among the loaded profiles, so it could "
             "not be cross-referenced. Load the matching profiles directory in "
             "the Profiles sub-tab.");
        break;
    }
    return out;
}
