#pragma once

#include <functional>
#include <vector>

#include <wx/wx.h>

#include "AuditParser.h"

class AppArmorPanel;
class AppArmorEventsPanel;
class AppArmorValidationPanel;
class RuleHitsPanel;
class wxNotebook;
class wxBookCtrlEvent;

// The outer "AppArmor" tab. Hosts an inner notebook with "Profiles" (what each
// profile allows/denies), "Denials" and "Allows" (which audit-log events are
// being hit), "Rule hits" (per-rule hit counts from the log) and "Validation"
// (profiles that fail apparmor_parser).
class AppArmorTab : public wxPanel {
public:
    using EventsProvider = std::function<const std::vector<audit::Event>&()>;

    AppArmorTab(wxWindow* parent, const wxString& initialDir,
                EventsProvider events);

    // Recompute the Denials and Allows sub-tabs from the current audit events.
    // Called when the audit history is cleared so they stop showing stale hits.
    void refreshEventViews();

private:
    void onSubPageChanged(wxBookCtrlEvent&);

    wxNotebook*              m_notebook   = nullptr;
    AppArmorPanel*           m_profiles   = nullptr;
    AppArmorEventsPanel*     m_denials    = nullptr;
    AppArmorEventsPanel*     m_allows     = nullptr;
    RuleHitsPanel*           m_ruleHits   = nullptr;
    AppArmorValidationPanel* m_validation = nullptr;

    wxDECLARE_EVENT_TABLE();
};
