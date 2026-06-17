#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

#include <wx/wx.h>
#include <wx/listctrl.h>

#include "AppArmorParser.h"
#include "AppArmorValidator.h"

// Inner sub-tab of the AppArmor tab: validates the profile files in the loaded
// directory with apparmor_parser and lists the ones that fail, with the error.
//
// Validation spawns one apparmor_parser per file, so it runs on a background
// thread and the UI polls progress with a timer to stay responsive.
class AppArmorValidationPanel : public wxPanel {
public:
    using ProfilesProvider = std::function<const apparmor::ParseResult&()>;

    AppArmorValidationPanel(wxWindow* parent, ProfilesProvider profiles);
    ~AppArmorValidationPanel() override;

private:
    void onValidate(wxCommandEvent&);
    void onItemSelected(wxListEvent&);
    void onPoll(wxTimerEvent&);

    void startValidation();
    void finishValidation();

    class ErrorList;
    wxString OnGetItemText(long item, long column) const;

    ProfilesProvider m_profiles;

    wxButton*     m_validateBtn = nullptr;
    wxStaticText* m_summary     = nullptr;
    ErrorList*    m_list        = nullptr;
    wxTextCtrl*   m_detail      = nullptr;
    wxTimer       m_timer;

    // The failing results, shown in the list (populated when the worker is done).
    std::vector<apparmor::ValidationResult> m_failures;

    // Worker state. m_results is written by the worker thread under m_mutex.
    std::thread                             m_worker;
    std::mutex                              m_mutex;
    std::vector<apparmor::ValidationResult> m_results; // guarded by m_mutex
    std::atomic<std::size_t>                m_done{0};
    std::atomic<bool>                       m_finished{false};
    std::atomic<bool>                       m_cancel{false};
    std::size_t                             m_total = 0;

    wxDECLARE_EVENT_TABLE();
};
