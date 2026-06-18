#include "AppArmorEventsPanel.h"

#include <algorithm>
#include <cctype>
#include <ctime>

#include <wx/menu.h>
#include <wx/msgdlg.h>
#include <wx/splitter.h>
#include <wx/textdlg.h>

#include "AppArmorEditor.h"

namespace {
enum {
    ID_DenSearch = wxID_HIGHEST + 200,
    ID_DenReload,
    ID_DenList,
    ID_DenAction,
    ID_DenAllow,
    ID_DenDeny,
    ID_DenReverse,
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

// Trim surrounding whitespace and any trailing commas, then re-add exactly one
// trailing comma so an edited rule stays well-formed.
std::string normalizeRule(std::string s) {
    auto isws = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && (isws(s.back()) || s.back() == ','))
        s.pop_back();
    const std::size_t first = s.find_first_not_of(" \t");
    if (first == std::string::npos)
        return {};
    return s.substr(first) + ',';
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

// Confirmation dialog for adding a rule: an editable rule field plus, for file
// rules, an "Owner only" checkbox that flips the `owner` qualifier in place so
// the user can choose between matching only their own files and any user's.
class RuleEditDialog : public wxDialog {
public:
    RuleEditDialog(wxWindow* parent, const wxString& prompt,
                   const wxString& rule, bool showOwner, bool ownerInitial)
        : wxDialog(parent, wxID_ANY, "Confirm AppArmor edit", wxDefaultPosition,
                   wxSize(720, -1)) {
        auto* sizer = new wxBoxSizer(wxVERTICAL);
        sizer->Add(new wxStaticText(this, wxID_ANY, prompt), 0,
                   wxALL | wxEXPAND, 12);

        m_text = new wxTextCtrl(this, wxID_ANY, rule);
        sizer->Add(m_text, 0, wxLEFT | wxRIGHT | wxEXPAND, 12);

        if (showOwner) {
            m_owner = new wxCheckBox(
                this, wxID_ANY,
                "Owner only - match only when the file is owned by the user "
                "running the program (otherwise it applies to any user)");
            m_owner->SetValue(ownerInitial);
            m_owner->Bind(wxEVT_CHECKBOX, &RuleEditDialog::onOwnerToggled, this);
            sizer->Add(m_owner, 0, wxALL, 12);
        }

        if (auto* btns = CreateButtonSizer(wxOK | wxCANCEL))
            sizer->Add(btns, 0, wxALL | wxEXPAND, 12);

        SetSizerAndFit(sizer);
        CentreOnParent();
        m_text->SetInsertionPointEnd();
        m_text->SetFocus();
    }

    wxString rule() const { return m_text->GetValue(); }

private:
    void onOwnerToggled(wxCommandEvent&) {
        m_text->ChangeValue(wxString::FromUTF8(apparmor::setOwnerQualifier(
            m_text->GetValue().ToStdString(), m_owner->GetValue())));
    }

    wxTextCtrl* m_text  = nullptr;
    wxCheckBox* m_owner = nullptr;
};
} // namespace

class AppArmorEventsPanel::DenialList : public wxListCtrl {
public:
    DenialList(AppArmorEventsPanel* owner, wxWindow* parent)
        : wxListCtrl(parent, ID_DenList, wxDefaultPosition, wxDefaultSize,
                     wxLC_REPORT | wxLC_VIRTUAL | wxLC_SINGLE_SEL),
          m_owner(owner) {}

protected:
    wxString OnGetItemText(long item, long column) const override {
        return m_owner->OnGetItemText(item, column);
    }

private:
    AppArmorEventsPanel* m_owner;
};

wxBEGIN_EVENT_TABLE(AppArmorEventsPanel, wxPanel)
    EVT_BUTTON(ID_DenReload, AppArmorEventsPanel::onRefresh)
    EVT_BUTTON(ID_DenAction, AppArmorEventsPanel::onActionButton)
    EVT_MENU(ID_DenAllow, AppArmorEventsPanel::onAllow)
    EVT_MENU(ID_DenDeny, AppArmorEventsPanel::onDeny)
    EVT_MENU(ID_DenReverse, AppArmorEventsPanel::onReverse)
    EVT_TEXT(ID_DenSearch, AppArmorEventsPanel::onFilterChanged)
    EVT_LIST_ITEM_SELECTED(ID_DenList, AppArmorEventsPanel::onItemSelected)
    EVT_LIST_ITEM_RIGHT_CLICK(ID_DenList, AppArmorEventsPanel::onListRightClick)
wxEND_EVENT_TABLE()

AppArmorEventsPanel::AppArmorEventsPanel(wxWindow* parent, Mode mode,
                                         EventsProvider events,
                                         ProfilesProvider profiles,
                                         ReloadProfiles reload)
    : wxPanel(parent), m_mode(mode), m_events(std::move(events)),
      m_profiles(std::move(profiles)), m_reloadProfiles(std::move(reload)) {
    const bool allows = m_mode == Mode::Allows;
    auto* sizer = new wxBoxSizer(wxVERTICAL);

    // --- Row 1: explanation + actions ---
    auto* topRow = new wxBoxSizer(wxHORIZONTAL);
    m_summary = new wxStaticText(
        this, wxID_ANY,
        allows ? "AppArmor allowed accesses from the loaded audit log. Load a "
                 "log in the Audit Log tab, then Refresh."
               : "AppArmor denials from the loaded audit log. Load a log in the "
                 "Audit Log tab, then Refresh.");
    topRow->Add(m_summary, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);
    // Reapply the edited profile into the kernel after writing. Only possible
    // as root (apparmor_parser needs privilege), so disable it otherwise.
    const bool root = apparmor::canReloadProfiles();
    m_reapplyChk = new wxCheckBox(
        this, wxID_ANY,
        root ? "Reapply profile (apparmor_parser -r)"
             : "Reapply profile (needs root)");
    m_reapplyChk->SetValue(root);
    m_reapplyChk->Enable(root);
    m_reapplyChk->SetToolTip(
        root ? "After writing the rule, reload the profile into the kernel so "
               "the change takes effect immediately."
             : "Run the tool as root to reapply profiles into the kernel.");
    topRow->Add(m_reapplyChk, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 16);

    // Per-denial actions live in a dropdown menu (also available by
    // right-clicking a row), so they stay visible regardless of selection.
    m_actionBtn = new wxButton(this, ID_DenAction, "Actions...");
    topRow->Add(m_actionBtn, 0, wxRIGHT, 16);
    topRow->Add(new wxButton(this, ID_DenReload, "Refresh"), 0);
    sizer->Add(topRow, 0, wxEXPAND | wxALL, 8);

    // --- Row 2: filter ---
    auto* filterRow = new wxBoxSizer(wxHORIZONTAL);
    filterRow->Add(new wxStaticText(this, wxID_ANY, "Filter:"), 0,
                   wxALIGN_CENTER_VERTICAL | wxRIGHT, 4);
    m_searchCtrl = new wxTextCtrl(this, ID_DenSearch, "", wxDefaultPosition,
                                  wxDefaultSize, wxTE_PROCESS_ENTER);
    m_searchCtrl->SetHint("profile, operation, path...");
    filterRow->Add(m_searchCtrl, 1, wxALIGN_CENTER_VERTICAL);
    sizer->Add(filterRow, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    // --- Splitter: denial list (top) + detail (bottom) ---
    auto* splitter = new wxSplitterWindow(this, wxID_ANY);
    splitter->SetMinimumPaneSize(120);

    m_list = new DenialList(this, splitter);
    m_list->AppendColumn("Profile", wxLIST_FORMAT_LEFT, 300);
    m_list->AppendColumn("Operation", wxLIST_FORMAT_LEFT, 90);
    m_list->AppendColumn(allows ? "Allowed target" : "Denied target",
                         wxLIST_FORMAT_LEFT, 300);
    m_list->AppendColumn("Mask", wxLIST_FORMAT_LEFT, 60);
    m_list->AppendColumn("Count", wxLIST_FORMAT_RIGHT, 70);
    m_list->AppendColumn(allows ? "Kind" : "Kind of denial", wxLIST_FORMAT_LEFT,
                         150);
    m_list->AppendColumn("Last seen", wxLIST_FORMAT_LEFT, 160);

    m_detail = new wxTextCtrl(splitter, wxID_ANY, "", wxDefaultPosition,
                              wxDefaultSize,
                              wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    m_detail->SetFont(wxFont(wxFontInfo(10).Family(wxFONTFAMILY_TELETYPE)));

    splitter->SplitHorizontally(m_list, m_detail, 320);
    sizer->Add(splitter, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    SetSizer(sizer);
}

void AppArmorEventsPanel::refresh() {
    const bool allows = m_mode == Mode::Allows;

    std::vector<apparmor::Denial> events;
    if (m_events) {
        for (const auto& ev : m_events()) {
            auto e = allows ? apparmor::allowFromEvent(ev)
                            : apparmor::denialFromEvent(ev);
            if (e)
                events.push_back(std::move(*e));
        }
    }

    m_groups = apparmor::aggregateDenials(events);
    if (m_profiles) {
        if (allows)
            apparmor::correlateAllows(m_groups, m_profiles().profiles);
        else
            apparmor::correlate(m_groups, m_profiles().profiles);
    }
    m_selected = -1;

    // Count by correlation; the meaningful buckets differ per mode.
    std::size_t a = 0, b = 0, unknown = 0;
    for (const auto& g : m_groups) {
        switch (g.correlation) {
        case apparmor::Correlation::ExplicitDeny:
        case apparmor::Correlation::AllowedByRule: ++a; break;
        case apparmor::Correlation::Implicit:
        case apparmor::Correlation::ComplainOnly:  ++b; break;
        case apparmor::Correlation::Unknown:       ++unknown; break;
        }
    }

    if (m_groups.empty()) {
        m_summary->SetLabel(
            allows ? "No AppArmor allowed accesses in the loaded audit log. "
                     "Load a log in the Audit Log tab, then Refresh."
                   : "No AppArmor denials in the loaded audit log. Load a log "
                     "in the Audit Log tab, then Refresh.");
    } else if (allows) {
        m_summary->SetLabel(wxString::Format(
            "%zu distinct allowed accesses  -  %zu by a rule, %zu complain-mode "
            "only, %zu profile not loaded",
            m_groups.size(), a, b, unknown));
    } else {
        m_summary->SetLabel(wxString::Format(
            "%zu distinct denials  -  %zu explicit deny rule, %zu implicit, "
            "%zu profile not loaded",
            m_groups.size(), a, b, unknown));
    }
    m_summary->Wrap(GetClientSize().GetWidth() - 120);
    Layout();

    rebuildFilter();
    m_detail->SetValue(
        m_groups.empty()
            ? wxString()
            : wxString(allows ? "Select an allowed access to see details and "
                                "the matching rule (if any)."
                              : "Select a denial to see details and the "
                                "matching rule (if any)."));
}

bool AppArmorEventsPanel::matches(const apparmor::DenialGroup& g) const {
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

void AppArmorEventsPanel::rebuildFilter() {
    m_filtered.clear();
    for (std::size_t i = 0; i < m_groups.size(); ++i)
        if (matches(m_groups[i]))
            m_filtered.push_back(i);
    m_list->SetItemCount(static_cast<long>(m_filtered.size()));
    m_list->Refresh();
}

void AppArmorEventsPanel::onRefresh(wxCommandEvent&) {
    refresh();
}

void AppArmorEventsPanel::onFilterChanged(wxCommandEvent&) {
    m_selected = -1;
    rebuildFilter();
}

void AppArmorEventsPanel::onItemSelected(wxListEvent& evt) {
    long row = evt.GetIndex();
    if (row < 0 || static_cast<std::size_t>(row) >= m_filtered.size())
        return;
    m_selected = static_cast<long>(m_filtered[row]);
    m_detail->SetValue(detailFor(m_groups[m_selected]));
}

bool AppArmorEventsPanel::selectionEditable() const {
    // A rule can be written for an event of a loaded profile in a class we can
    // express: implicit denials (Denials mode) or complain-only allows (Allows
    // mode, where codifying the rule is what makes it survive enforce mode).
    if (m_selected < 0 || static_cast<std::size_t>(m_selected) >= m_groups.size())
        return false;
    const apparmor::DenialGroup& g = m_groups[m_selected];
    const bool haveDir = m_profiles && !m_profiles().directory.empty();
    const auto want = m_mode == Mode::Allows ? apparmor::Correlation::ComplainOnly
                                             : apparmor::Correlation::Implicit;
    return g.correlation == want && !g.profileFile.empty() && haveDir &&
           apparmor::buildRule(g.sample, apparmor::Decision::Allow).has_value();
}

bool AppArmorEventsPanel::selectionReversible() const {
    // Reversing applies only to an explicit deny rule (Denials mode).
    if (m_mode != Mode::Denials)
        return false;
    if (m_selected < 0 || static_cast<std::size_t>(m_selected) >= m_groups.size())
        return false;
    const apparmor::DenialGroup& g = m_groups[m_selected];
    const bool haveDir = m_profiles && !m_profiles().directory.empty();
    return g.correlation == apparmor::Correlation::ExplicitDeny &&
           !g.matchedRule.empty() && !g.profileFile.empty() && haveDir;
}

void AppArmorEventsPanel::popupActionMenu() {
    wxMenu menu;
    if (selectionEditable()) {
        menu.Append(ID_DenAllow, "Allow this access in the profile");
        menu.Append(ID_DenDeny, "Deny this access in the profile");
    } else if (selectionReversible()) {
        menu.Append(ID_DenReverse, "Reverse this deny rule to allow");
    } else {
        wxMenuItem* hint = menu.Append(
            wxID_ANY, m_mode == Mode::Allows
                          ? "Select a complain-mode-only allow to make it a rule"
                          : "Select an implicit denial (to allow/deny) or an "
                            "explicit-deny one (to reverse)");
        hint->Enable(false);
    }
    PopupMenu(&menu);
}

void AppArmorEventsPanel::onActionButton(wxCommandEvent&) {
    popupActionMenu();
}

void AppArmorEventsPanel::onListRightClick(wxListEvent& evt) {
    long row = evt.GetIndex();
    if (row >= 0 && static_cast<std::size_t>(row) < m_filtered.size()) {
        m_selected = static_cast<long>(m_filtered[row]);
        m_detail->SetValue(detailFor(m_groups[m_selected]));
    }
    popupActionMenu();
}

void AppArmorEventsPanel::onAllow(wxCommandEvent&) {
    applyDecision(apparmor::Decision::Allow);
}

void AppArmorEventsPanel::onDeny(wxCommandEvent&) {
    applyDecision(apparmor::Decision::Deny);
}

void AppArmorEventsPanel::onReverse(wxCommandEvent&) {
    applyReverse();
}

// Shared tail for both edit operations: optionally reapply, report, reload.
bool AppArmorEventsPanel::finishEdit(const apparmor::EditResult& r,
                                      const wxString& file) {
    if (!r.ok) {
        wxMessageBox(wxString::FromUTF8(r.message), "AppArmor edit failed",
                     wxOK | wxICON_ERROR, this);
        return false;
    }

    wxString outcome = wxString::FromUTF8(r.message);
    long icon = wxICON_INFORMATION;
    if (m_reapplyChk && m_reapplyChk->IsEnabled() && m_reapplyChk->IsChecked()) {
        apparmor::ReloadResult rr =
            apparmor::reloadProfile(file.ToStdString());
        outcome += "\n\n" + wxString::FromUTF8(rr.message);
        if (!rr.ok)
            icon = wxICON_WARNING; // change was written, but reload failed
    } else {
        outcome += "\n\nReload AppArmor (apparmor_parser -r) to apply it.";
    }
    wxMessageBox(outcome, "AppArmor edit", wxOK | icon, this);

    // Re-parse the profiles and recompute so the change is reflected.
    if (m_reloadProfiles)
        m_reloadProfiles();
    refresh();
    return true;
}

void AppArmorEventsPanel::applyReverse() {
    if (!selectionReversible())
        return;
    // Copy by value: a modal dialog and finishEdit() below can rebuild
    // m_groups, so we must not hold a reference into it across them.
    const apparmor::DenialGroup g = m_groups[m_selected];

    const wxString dir = wxString::FromUTF8(m_profiles().directory);
    const wxString file = dir + "/" + wxString::FromUTF8(g.profileFile);

    wxString msg = "Reverse this deny rule into an allow rule?\n\n";
    msg += "    " + wxString::FromUTF8(g.matchedRule) + "\n\n";
    msg += "Profile: " + wxString::FromUTF8(g.sample.profile) + "\n";
    msg += "File:    " + file + "\n\n";
    msg += "The 'deny' qualifier is removed so the access is allowed (crash-"
           "safely via a temp file).";

    wxMessageDialog confirm(this, msg, "Confirm AppArmor edit",
                            wxYES_NO | wxICON_QUESTION);
    confirm.SetYesNoLabels("&Reverse rule", "&Cancel");
    if (confirm.ShowModal() != wxID_YES)
        return;

    apparmor::EditResult r = apparmor::reverseDenyRule(
        file.ToStdString(), g.sample.profile, g.matchedRule);
    finishEdit(r, file);
}

void AppArmorEventsPanel::applyDecision(apparmor::Decision decision) {
    if (m_selected < 0 || static_cast<std::size_t>(m_selected) >= m_groups.size())
        return;
    // Copy by value: a modal dialog and finishEdit() below can rebuild
    // m_groups, so we must not hold a reference into it across them.
    const apparmor::DenialGroup g = m_groups[m_selected];

    auto rule = apparmor::buildRule(g.sample, decision);
    if (!rule) {
        wxMessageBox("Cannot generate a rule for this denial class.",
                     "AppArmor edit", wxOK | wxICON_INFORMATION, this);
        return;
    }

    const wxString dir = wxString::FromUTF8(m_profiles().directory);
    const wxString file = dir + "/" + wxString::FromUTF8(g.profileFile);
    const wxString verb = (decision == apparmor::Decision::Deny) ? "Deny"
                                                                 : "Allow";

    // Let the user edit the rule before it is written. This matters most for
    // path rules, where you usually want to widen the exact denied path into a
    // glob (e.g. /home/*/.cache/** rather than one specific file), and to pick
    // owner-only versus any-user via the checkbox.
    wxString prompt = verb + " this access by adding a rule to the profile.\n"
                             "Edit it if you want (e.g. widen a path with "
                             "* or ** globs):\n\n";
    prompt += "Profile: " + wxString::FromUTF8(g.sample.profile) + "\n";
    prompt += "File:    " + file;

    RuleEditDialog dlg(this, prompt, wxString::FromUTF8(*rule),
                       apparmor::ruleSupportsOwner(*rule), g.sample.owner);
    if (dlg.ShowModal() != wxID_OK)
        return;

    const std::string finalRule = normalizeRule(dlg.rule().ToStdString());
    if (finalRule.empty()) {
        wxMessageBox("The rule is empty; nothing was written.", "AppArmor edit",
                     wxOK | wxICON_INFORMATION, this);
        return;
    }

    apparmor::EditResult r = apparmor::addRuleToProfile(
        file.ToStdString(), g.sample.profile, finalRule);
    finishEdit(r, file);
}

wxString AppArmorEventsPanel::OnGetItemText(long item, long column) const {
    if (item < 0 || static_cast<std::size_t>(item) >= m_filtered.size())
        return {};
    const apparmor::DenialGroup& g = m_groups[m_filtered[item]];
    const apparmor::Denial& d = g.sample;
    switch (column) {
    case kColProfile: return wxString::FromUTF8(d.profile);
    case kColOp:      return wxString::FromUTF8(d.operation);
    case kColTarget:  return wxString::FromUTF8(d.target);
    case kColDenied:  return wxString::FromUTF8(
        m_mode == Mode::Allows ? d.requestedMask : d.deniedMask);
    case kColCount:   return wxString::Format("%zu", g.count);
    case kColKind:    return apparmor::correlationName(g.correlation);
    case kColLast:    return formatTime(g.lastSeen);
    default:          return {};
    }
}

wxString AppArmorEventsPanel::detailFor(const apparmor::DenialGroup& g) const {
    const apparmor::Denial& d = g.sample;
    wxString out;
    auto line = [&](const wxString& s) { out += s + "\n"; };

    const bool allows = m_mode == Mode::Allows;
    line("Profile:     " + wxString::FromUTF8(d.profile));
    line("Operation:   " + wxString::FromUTF8(d.operation) +
         (d.klass.empty() ? wxString()
                          : "   (class " + wxString::FromUTF8(d.klass) + ")"));
    line(wxString(allows ? "Allowed:     " : "Denied:      ") +
         wxString::FromUTF8(d.target));
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
        line("No explicit deny rule matches - this is an implicit denial: the "
             "profile simply does not allow this access.");
        line("");
        line("To permit it, add an allow rule to the profile; to silence it "
             "without allowing, add a `deny` rule.");
        break;
    case apparmor::Correlation::AllowedByRule:
        if (!g.matchedRule.empty()) {
            line("Allowed by this rule in the profile:");
            line("    " + wxString::FromUTF8(g.matchedRule));
        } else {
            line("Allowed by a rule that is not in this profile file - it most "
                 "likely comes from an included abstraction.");
        }
        break;
    case apparmor::Correlation::ComplainOnly:
        line("Allowed only because the profile is in complain mode - no rule "
             "permits this, so it WOULD BE DENIED once the profile enforces.");
        line("");
        line("Use the Actions menu to add an allow rule now, so the access "
             "keeps working after you switch the profile back to enforce.");
        break;
    case apparmor::Correlation::Unknown:
        line(wxString(allows ? "The allowed" : "The denied") +
             " profile is not among the loaded profiles, so it could not be "
             "cross-referenced. Load the matching profiles directory in the "
             "Profiles sub-tab.");
        break;
    }
    return out;
}
