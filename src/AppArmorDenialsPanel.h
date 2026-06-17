#pragma once

#include <functional>
#include <vector>

#include <wx/wx.h>
#include <wx/listctrl.h>

#include "AppArmorDenials.h"
#include "AppArmorParser.h"
#include "AuditParser.h"

// Inner sub-tab of the AppArmor tab: shows the AppArmor DENIED events found in
// the currently loaded audit log, aggregated and correlated with the loaded
// profiles' deny rules.
class AppArmorDenialsPanel : public wxPanel {
public:
    // eventsProvider yields the audit events currently loaded in the audit tab;
    // profilesProvider yields the currently parsed AppArmor profiles.
    using EventsProvider = std::function<const std::vector<audit::Event>&()>;
    using ProfilesProvider = std::function<const std::vector<apparmor::Profile>&()>;

    AppArmorDenialsPanel(wxWindow* parent, EventsProvider events,
                         ProfilesProvider profiles);

    // Recompute from the current audit events + profiles.
    void refresh();

private:
    void onRefresh(wxCommandEvent&);
    void onFilterChanged(wxCommandEvent&);
    void onItemSelected(wxListEvent&);

    void rebuildFilter();
    bool matches(const apparmor::DenialGroup& g) const;
    wxString detailFor(const apparmor::DenialGroup& g) const;

    class DenialList;
    wxString OnGetItemText(long item, long column) const;

    EventsProvider   m_events;
    ProfilesProvider m_profiles;

    wxTextCtrl*  m_searchCtrl = nullptr;
    wxStaticText* m_summary   = nullptr;
    DenialList*  m_list       = nullptr;
    wxTextCtrl*  m_detail     = nullptr;

    std::vector<apparmor::DenialGroup> m_groups;
    std::vector<std::size_t>           m_filtered;

    wxDECLARE_EVENT_TABLE();
};
