#include "AppArmorPanel.h"

#include <algorithm>
#include <cctype>
#include <map>

#include <wx/dirdlg.h>
#include <wx/splitter.h>

namespace {
enum {
    ID_AaDir = wxID_HIGHEST + 100,
    ID_AaBrowse,
    ID_AaReload,
    ID_AaSearch,
    ID_AaList,
};

constexpr int kColName = 0;
constexpr int kColMode = 1;
constexpr int kColGives = 2;
constexpr int kColTakes = 3;
constexpr int kColSource = 4;

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}
} // namespace

// Virtual list: profiles (and their nested children) flattened to rows.
class AppArmorPanel::ProfileList : public wxListCtrl {
public:
    ProfileList(AppArmorPanel* owner, wxWindow* parent)
        : wxListCtrl(parent, ID_AaList, wxDefaultPosition, wxDefaultSize,
                     wxLC_REPORT | wxLC_VIRTUAL | wxLC_SINGLE_SEL),
          m_owner(owner) {}

protected:
    wxString OnGetItemText(long item, long column) const override {
        return m_owner->OnGetItemText(item, column);
    }

private:
    AppArmorPanel* m_owner;
};

wxBEGIN_EVENT_TABLE(AppArmorPanel, wxPanel)
    EVT_BUTTON(ID_AaBrowse, AppArmorPanel::onBrowse)
    EVT_BUTTON(ID_AaReload, AppArmorPanel::onReload)
    EVT_TEXT(ID_AaSearch, AppArmorPanel::onFilterChanged)
    EVT_LIST_ITEM_SELECTED(ID_AaList, AppArmorPanel::onItemSelected)
wxEND_EVENT_TABLE()

AppArmorPanel::AppArmorPanel(wxWindow* parent, const wxString& initialDir)
    : wxPanel(parent) {
    auto* sizer = new wxBoxSizer(wxVERTICAL);

    // --- Row 1: directory + browse + reload ---
    auto* dirRow = new wxBoxSizer(wxHORIZONTAL);
    dirRow->Add(new wxStaticText(this, wxID_ANY, "Profiles dir:"), 0,
                wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    m_dirCtrl = new wxTextCtrl(this, ID_AaDir, initialDir, wxDefaultPosition,
                               wxDefaultSize, wxTE_PROCESS_ENTER);
    dirRow->Add(m_dirCtrl, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    dirRow->Add(new wxButton(this, ID_AaBrowse, "Browse…"), 0, wxRIGHT, 6);
    dirRow->Add(new wxButton(this, ID_AaReload, "Reload"), 0);
    sizer->Add(dirRow, 0, wxEXPAND | wxALL, 8);

    // --- Row 2: filter ---
    auto* filterRow = new wxBoxSizer(wxHORIZONTAL);
    filterRow->Add(new wxStaticText(this, wxID_ANY, "Filter:"), 0,
                   wxALIGN_CENTER_VERTICAL | wxRIGHT, 4);
    m_searchCtrl = new wxTextCtrl(this, ID_AaSearch, "", wxDefaultPosition,
                                  wxDefaultSize, wxTE_PROCESS_ENTER);
    m_searchCtrl->SetHint("profile name, path or rule…");
    filterRow->Add(m_searchCtrl, 1, wxALIGN_CENTER_VERTICAL);
    sizer->Add(filterRow, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    // --- Splitter: profile list (top) + detail (bottom) ---
    auto* splitter = new wxSplitterWindow(this, wxID_ANY);
    splitter->SetMinimumPaneSize(120);

    m_list = new ProfileList(this, splitter);
    m_list->AppendColumn("Profile", wxLIST_FORMAT_LEFT, 300);
    m_list->AppendColumn("Mode", wxLIST_FORMAT_LEFT, 90);
    m_list->AppendColumn("Gives", wxLIST_FORMAT_RIGHT, 60);
    m_list->AppendColumn("Takes", wxLIST_FORMAT_RIGHT, 60);
    m_list->AppendColumn("Source file", wxLIST_FORMAT_LEFT, 360);

    m_detail = new wxTextCtrl(splitter, wxID_ANY, "", wxDefaultPosition,
                              wxDefaultSize,
                              wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    m_detail->SetFont(wxFont(wxFontInfo(10).Family(wxFONTFAMILY_TELETYPE)));

    splitter->SplitHorizontally(m_list, m_detail, 320);
    sizer->Add(splitter, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    SetSizer(sizer);

    if (!initialDir.empty() && wxDirExists(initialDir))
        loadDir(initialDir);
    else
        m_detail->SetValue(
            "Choose a directory of AppArmor profiles (e.g. /etc/apparmor.d or a "
            "readable copy) and press Reload.");
}

void AppArmorPanel::flatten(const apparmor::Profile& p, int depth) {
    m_rows.push_back(Row{&p, depth});
    for (const auto& c : p.children)
        flatten(c, depth + 1);
}

void AppArmorPanel::loadDir(const wxString& dir) {
    m_result = apparmor::parseDirectory(dir.ToStdString());

    m_rows.clear();
    for (const auto& p : m_result.profiles)
        flatten(p, 0);

    rebuildFilter();

    wxString status = wxString::Format(
        "%zu profiles from %zu files", m_rows.size(), m_result.filesParsed);
    if (!m_result.errors.empty())
        status += wxString::Format("  (%zu unreadable)",
                                   m_result.errors.size());
    m_detail->SetValue(status + ".\n\nSelect a profile to see what it gives "
                                "and takes.");
}

bool AppArmorPanel::matches(const apparmor::Profile& p) const {
    const wxString raw = m_searchCtrl ? m_searchCtrl->GetValue() : wxString();
    if (raw.empty())
        return true;
    const std::string needle = toLower(raw.ToStdString());

    if (toLower(p.name).find(needle) != std::string::npos)
        return true;
    if (toLower(p.attachment).find(needle) != std::string::npos)
        return true;
    if (toLower(p.sourceFile).find(needle) != std::string::npos)
        return true;
    for (const auto& r : p.rules)
        if (toLower(r.raw).find(needle) != std::string::npos)
            return true;
    return false;
}

void AppArmorPanel::rebuildFilter() {
    m_filtered.clear();
    for (std::size_t i = 0; i < m_rows.size(); ++i)
        if (matches(*m_rows[i].prof))
            m_filtered.push_back(i);
    m_list->SetItemCount(static_cast<long>(m_filtered.size()));
    m_list->Refresh();
}

void AppArmorPanel::onBrowse(wxCommandEvent&) {
    wxDirDialog dlg(this, "Choose an AppArmor profiles directory",
                    m_dirCtrl->GetValue());
    if (dlg.ShowModal() == wxID_OK) {
        m_dirCtrl->SetValue(dlg.GetPath());
        loadDir(dlg.GetPath());
    }
}

void AppArmorPanel::onReload(wxCommandEvent&) {
    loadDir(m_dirCtrl->GetValue());
}

void AppArmorPanel::onFilterChanged(wxCommandEvent&) {
    rebuildFilter();
}

void AppArmorPanel::onItemSelected(wxListEvent& evt) {
    long row = evt.GetIndex();
    if (row < 0 || static_cast<std::size_t>(row) >= m_filtered.size())
        return;
    const apparmor::Profile& p = *m_rows[m_filtered[row]].prof;
    m_detail->SetValue(detailFor(p));
}

wxString AppArmorPanel::OnGetItemText(long item, long column) const {
    if (item < 0 || static_cast<std::size_t>(item) >= m_filtered.size())
        return {};
    const Row& r = m_rows[m_filtered[item]];
    const apparmor::Profile& p = *r.prof;
    switch (column) {
    case kColName: {
        wxString name = wxString::FromUTF8(p.name.empty() ? p.attachment
                                                          : p.name);
        if (r.depth > 0)
            name = wxString(' ', r.depth * 2) + "↳ " + name;
        return name;
    }
    case kColMode:   return p.complain() ? "complain" : "enforce";
    case kColGives:  return wxString::Format("%zu", p.allowCount());
    case kColTakes:  return wxString::Format("%zu", p.denyCount());
    case kColSource: return wxString::FromUTF8(p.sourceFile);
    default:         return {};
    }
}

wxString AppArmorPanel::detailFor(const apparmor::Profile& p) const {
    using apparmor::Decision;
    using apparmor::Rule;
    using apparmor::RuleKind;

    wxString out;
    auto line = [&](const wxString& s) { out += s + "\n"; };

    line("Profile:     " + wxString::FromUTF8(p.name.empty() ? "(unnamed)"
                                                             : p.name));
    if (!p.attachment.empty() && p.attachment != p.name)
        line("Attaches to: " + wxString::FromUTF8(p.attachment));
    line(wxString("Mode:        ") +
         (p.complain() ? "complain (rules are logged, not enforced)"
                       : "enforce"));
    if (!p.flags.empty()) {
        wxString f;
        for (const auto& fl : p.flags) {
            if (!f.empty())
                f += ", ";
            f += wxString::FromUTF8(fl);
        }
        line("Flags:       " + f);
    }
    line("Source:      " + wxString::FromUTF8(p.sourceFile) +
         wxString::Format(":%d", p.startLine));

    if (!p.includes.empty()) {
        line("");
        line("Includes (inherited rules from abstractions):");
        for (const auto& inc : p.includes)
            line("    " + wxString::FromUTF8(inc));
    }

    // Group a set of rules by kind for either the gives or takes section.
    auto section = [&](const wxString& heading, Decision want) {
        std::map<RuleKind, std::vector<const Rule*>> byKind;
        for (const auto& r : p.rules)
            if (r.decision == want)
                byKind[r.kind].push_back(&r);

        line("");
        if (byKind.empty()) {
            line(heading + "  (none)");
            return;
        }
        line(heading);
        for (const auto& [kind, rules] : byKind) {
            line(wxString("  ") + apparmor::ruleKindName(kind) + ":");
            for (const Rule* r : rules) {
                wxString lead;
                if (r->kind == RuleKind::File && !r->perms.empty()) {
                    lead = wxString::Format("    %-8s %s", r->perms.c_str(),
                                            r->target.c_str());
                    if (r->owner)
                        lead += "   (owner only)";
                    const std::string desc = apparmor::describePerms(r->perms);
                    if (!desc.empty())
                        lead += "   [" + wxString::FromUTF8(desc) + "]";
                } else {
                    lead = "    " + wxString::FromUTF8(r->raw);
                }
                if (r->audit)
                    lead += "   (audited)";
                line(lead);
            }
        }
    };

    section("GIVES — access this profile allows:", Decision::Allow);
    section("TAKES — access this profile explicitly denies:", Decision::Deny);

    if (!p.children.empty()) {
        line("");
        line("Child profiles (listed as their own rows):");
        for (const auto& c : p.children)
            line("    " + wxString::FromUTF8(c.name));
    }

    return out;
}
