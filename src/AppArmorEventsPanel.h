#pragma once

#include <functional>
#include <vector>

#include <wx/wx.h>
#include <wx/listctrl.h>

#include "AppArmorDenials.h"
#include "AppArmorEditor.h"
#include "AppArmorParser.h"
#include "AuditParser.h"

// Inner sub-tab of the AppArmor tab: shows the AppArmor mediation events found
// in the currently loaded audit log, aggregated and correlated with the loaded
// profiles' rules. The same panel serves the DENIED events ("Denials") and the
// ALLOWED events ("Allows"), selected by Mode.
class AppArmorEventsPanel : public wxPanel {
public:
    enum class Mode { Denials, Allows };

    // eventsProvider yields the audit events currently loaded in the audit tab;
    // profilesProvider yields the currently parsed AppArmor profiles (with the
    // directory they came from); reloadProfiles re-parses them after an edit.
    using EventsProvider = std::function<const std::vector<audit::Event>&()>;
    using ProfilesProvider = std::function<const apparmor::ParseResult&()>;
    using ReloadProfiles = std::function<void()>;

    AppArmorEventsPanel(wxWindow* parent, Mode mode, EventsProvider events,
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
    // After allowing a ptrace/signal access, offer to add the complementary
    // rule the peer profile needs (AppArmor mediates these on both ends).
    void maybeAddPeerRule(const apparmor::DenialGroup& g,
                          apparmor::Decision decision, const wxString& dir);
    // morePermissive: the write grants access (allow / deny-reversal). Such a
    // change is not picked up by an already-running process that has
    // no_new_privs set, so the success message then suggests restarting it.
    bool finishEdit(const apparmor::EditResult& r, const wxString& file,
                    bool morePermissive);

    class DenialList;
    wxString OnGetItemText(long item, long column) const;

    Mode             m_mode;
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
