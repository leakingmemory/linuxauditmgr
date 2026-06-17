#pragma once

#include <functional>
#include <vector>

#include <wx/wx.h>
#include <wx/listctrl.h>

#include "AppArmorDenials.h"
#include "AppArmorEditor.h"
#include "AppArmorParser.h"
#include "AuditParser.h"

// Inner sub-tab of the AppArmor tab: shows the AppArmor DENIED events found in
// the currently loaded audit log, aggregated and correlated with the loaded
// profiles' deny rules.
class AppArmorDenialsPanel : public wxPanel {
public:
    // eventsProvider yields the audit events currently loaded in the audit tab;
    // profilesProvider yields the currently parsed AppArmor profiles (with the
    // directory they came from); reloadProfiles re-parses them after an edit.
    using EventsProvider = std::function<const std::vector<audit::Event>&()>;
    using ProfilesProvider = std::function<const apparmor::ParseResult&()>;
    using ReloadProfiles = std::function<void()>;

    AppArmorDenialsPanel(wxWindow* parent, EventsProvider events,
                         ProfilesProvider profiles, ReloadProfiles reload);

    // Recompute from the current audit events + profiles.
    void refresh();

private:
    void onRefresh(wxCommandEvent&);
    void onFilterChanged(wxCommandEvent&);
    void onItemSelected(wxListEvent&);
    void onAllow(wxCommandEvent&);
    void onDeny(wxCommandEvent&);
    void onReverse(wxCommandEvent&);
    void onActionButton(wxCommandEvent&);
    void onListRightClick(wxListEvent&);

    void rebuildFilter();
    bool matches(const apparmor::DenialGroup& g) const;
    wxString detailFor(const apparmor::DenialGroup& g) const;
    bool selectionEditable() const;
    bool selectionReversible() const;
    void popupActionMenu();
    void applyDecision(apparmor::Decision decision);
    void applyReverse();
    bool finishEdit(const apparmor::EditResult& r, const wxString& file);

    class DenialList;
    wxString OnGetItemText(long item, long column) const;

    EventsProvider   m_events;
    ProfilesProvider m_profiles;
    ReloadProfiles   m_reloadProfiles;

    wxTextCtrl*  m_searchCtrl = nullptr;
    wxStaticText* m_summary   = nullptr;
    wxButton*    m_actionBtn  = nullptr;
    wxCheckBox*  m_reapplyChk = nullptr;
    DenialList*  m_list       = nullptr;
    wxTextCtrl*  m_detail     = nullptr;

    std::vector<apparmor::DenialGroup> m_groups;
    std::vector<std::size_t>           m_filtered;
    long                               m_selected = -1; // index into m_groups

    wxDECLARE_EVENT_TABLE();
};
