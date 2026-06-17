#pragma once

#include <functional>
#include <vector>

#include <wx/wx.h>

#include "AuditParser.h"

class AppArmorPanel;
class AppArmorEventsPanel;
class wxNotebook;
class wxBookCtrlEvent;

// The outer "AppArmor" tab. Hosts an inner notebook with a "Profiles" sub-tab
// (what each profile allows/denies), a "Denials" sub-tab (which denials in the
// audit log are being hit) and an "Allows" sub-tab (which allows are).
class AppArmorTab : public wxPanel {
public:
    using EventsProvider = std::function<const std::vector<audit::Event>&()>;

    AppArmorTab(wxWindow* parent, const wxString& initialDir,
                EventsProvider events);

private:
    void onSubPageChanged(wxBookCtrlEvent&);

    wxNotebook*          m_notebook = nullptr;
    AppArmorPanel*       m_profiles = nullptr;
    AppArmorEventsPanel* m_denials  = nullptr;
    AppArmorEventsPanel* m_allows   = nullptr;

    wxDECLARE_EVENT_TABLE();
};
