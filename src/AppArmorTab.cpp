#include "AppArmorTab.h"

#include <wx/notebook.h>

#include "AppArmorDenialsPanel.h"
#include "AppArmorPanel.h"

wxBEGIN_EVENT_TABLE(AppArmorTab, wxPanel)
    EVT_NOTEBOOK_PAGE_CHANGED(wxID_ANY, AppArmorTab::onSubPageChanged)
wxEND_EVENT_TABLE()

AppArmorTab::AppArmorTab(wxWindow* parent, const wxString& initialDir,
                         EventsProvider events)
    : wxPanel(parent) {
    m_notebook = new wxNotebook(this, wxID_ANY);

    m_profiles = new AppArmorPanel(m_notebook, initialDir);

    // The denials view reads the live audit events from the audit tab and the
    // profiles currently loaded in the Profiles sub-tab.
    m_denials = new AppArmorDenialsPanel(
        m_notebook, std::move(events),
        [this]() -> const std::vector<apparmor::Profile>& {
            return m_profiles->result().profiles;
        });

    m_notebook->AddPage(m_profiles, "Profiles");
    m_notebook->AddPage(m_denials, "Denials");

    auto* sizer = new wxBoxSizer(wxVERTICAL);
    sizer->Add(m_notebook, 1, wxEXPAND);
    SetSizer(sizer);
}

void AppArmorTab::onSubPageChanged(wxBookCtrlEvent& evt) {
    // Recompute denials when that sub-tab is brought to the front, so it
    // reflects the latest audit log and loaded profiles.
    if (m_notebook && m_notebook->GetPage(evt.GetSelection()) == m_denials)
        m_denials->refresh();
    evt.Skip();
}
