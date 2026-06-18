#pragma once

#include <functional>
#include <vector>

#include <wx/wx.h>
#include <wx/listctrl.h>

#include "AppArmorDenials.h"
#include "AppArmorParser.h"
#include "AuditParser.h"

// Inner sub-tab of the AppArmor tab: pick a loaded profile and see each of its
// rules with the number of times the loaded audit log exercised it. This is the
// inverse of the Denials/Allows views - those start from events and find the
// rule; this starts from the rules and counts the events.
class RuleHitsPanel : public wxPanel {
public:
    using EventsProvider = std::function<const std::vector<audit::Event>&()>;
    using ProfilesProvider = std::function<const apparmor::ParseResult&()>;

    RuleHitsPanel(wxWindow* parent, EventsProvider events,
                  ProfilesProvider profiles);

    // Re-extract the audit events, repopulate the profile picker and recompute
    // the hit counts for the selected profile.
    void refresh();

private:
    void onProfileChosen(wxCommandEvent&);
    void onFilterChanged(wxCommandEvent&);
    void onItemSelected(wxListEvent&);

    void flattenInto(const apparmor::Profile& p, int depth);
    void recompute();          // hits for the currently selected profile
    void rebuildFilter();      // apply text filter, sort by hit count desc
    bool matchesFilter(std::size_t ruleIdx) const;
    wxString detailFor(std::size_t ruleIdx) const;

    class RuleList;
    wxString OnGetItemText(long item, long column) const;

    EventsProvider   m_events;
    ProfilesProvider m_profiles;

    wxChoice*     m_profileChoice = nullptr;
    wxStaticText* m_summary       = nullptr;
    wxTextCtrl*   m_searchCtrl    = nullptr;
    RuleList*     m_list          = nullptr;
    wxTextCtrl*   m_detail        = nullptr;

    // The audit log split into AppArmor denial / allow records, rebuilt on
    // refresh() and reused as the user switches profiles.
    std::vector<apparmor::Denial> m_denials;
    std::vector<apparmor::Denial> m_allows;

    // Profiles flattened (children included) parallel to the picker entries.
    std::vector<const apparmor::Profile*> m_profileItems;
    const apparmor::Profile*              m_current = nullptr;

    std::vector<apparmor::RuleHitCount> m_hits;     // parallel to m_current->rules
    std::vector<std::size_t>            m_filtered; // rule indices, sorted/filtered

    wxDECLARE_EVENT_TABLE();
};
