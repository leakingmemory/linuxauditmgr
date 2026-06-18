#include "AppArmorTab.h"

#include <wx/notebook.h>

#include "AppArmorEventsPanel.h"
#include "AppArmorPanel.h"
#include "AppArmorValidationPanel.h"

wxBEGIN_EVENT_TABLE(AppArmorTab, wxPanel)
    EVT_NOTEBOOK_PAGE_CHANGED(wxID_ANY, AppArmorTab::onSubPageChanged)
wxEND_EVENT_TABLE()

AppArmorTab::AppArmorTab(wxWindow* parent, const wxString& initialDir,
                         EventsProvider events)
    : wxPanel(parent) {
    m_notebook = new wxNotebook(this, wxID_ANY);

    m_profiles = new AppArmorPanel(m_notebook, initialDir);

    // The denials/allows views read the live audit events from the audit tab
    // and the profiles loaded in the Profiles sub-tab, and can ask it to
    // re-parse after writing a rule.
    auto profiles = [this]() -> const apparmor::ParseResult& {
        return m_profiles->result();
    };
    auto reload = [this]() { m_profiles->reload(); };

    m_denials = new AppArmorEventsPanel(m_notebook,
                                        AppArmorEventsPanel::Mode::Denials,
                                        events, profiles, reload);
    m_allows = new AppArmorEventsPanel(m_notebook,
                                       AppArmorEventsPanel::Mode::Allows,
                                       std::move(events), profiles, reload);
    m_validation = new AppArmorValidationPanel(m_notebook, profiles, reload);

    m_notebook->AddPage(m_profiles, "Profiles");
    m_notebook->AddPage(m_denials, "Denials");
    m_notebook->AddPage(m_allows, "Allows");
    m_notebook->AddPage(m_validation, "Validation");

    auto* sizer = new wxBoxSizer(wxVERTICAL);
    sizer->Add(m_notebook, 1, wxEXPAND);
    SetSizer(sizer);
}

void AppArmorTab::refreshEventViews() {
    if (m_denials)
        m_denials->refresh();
    if (m_allows)
        m_allows->refresh();
}

void AppArmorTab::onSubPageChanged(wxBookCtrlEvent& evt) {
    // Recompute a sub-tab when it is brought to the front, so it reflects the
    // latest audit log and loaded profiles.
    if (m_notebook) {
        wxWindow* page = m_notebook->GetPage(evt.GetSelection());
        if (page == m_denials)
            m_denials->refresh();
        else if (page == m_allows)
            m_allows->refresh();
    }
    evt.Skip();
}
