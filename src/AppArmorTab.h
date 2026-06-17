#pragma once

#include <functional>
#include <vector>

#include <wx/wx.h>

#include "AuditParser.h"

class AppArmorPanel;
class AppArmorDenialsPanel;
class wxNotebook;
class wxBookCtrlEvent;

// The outer "AppArmor" tab. Hosts an inner notebook with a "Profiles" sub-tab
// (what each profile allows/denies) and a "Denials" sub-tab (which denials in
// the audit log are actually being hit).
class AppArmorTab : public wxPanel {
public:
    using EventsProvider = std::function<const std::vector<audit::Event>&()>;

    AppArmorTab(wxWindow* parent, const wxString& initialDir,
                EventsProvider events);

private:
    void onSubPageChanged(wxBookCtrlEvent&);

    wxNotebook*           m_notebook = nullptr;
    AppArmorPanel*        m_profiles = nullptr;
    AppArmorDenialsPanel* m_denials  = nullptr;

    wxDECLARE_EVENT_TABLE();
};
