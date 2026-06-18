#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <wx/wx.h>
#include <wx/listctrl.h>

#include "AppArmorParser.h"

// Inner sub-tab of the AppArmor tab. Validates the profile files in the loaded
// directory with apparmor_parser and lists the ones that fail; for the files
// that pass, it also flags those whose rules are not in canonical form and can
// normalize them (with a diff shown before writing).
//
// Validation/normalization run one apparmor_parser per file, so the work is
// done on a background thread and the UI polls progress with a timer.
class AppArmorValidationPanel : public wxPanel {
public:
    using ProfilesProvider = std::function<const apparmor::ParseResult&()>;
    using ReloadProfiles = std::function<void()>;

    AppArmorValidationPanel(wxWindow* parent, ProfilesProvider profiles,
                            ReloadProfiles reload);
    ~AppArmorValidationPanel() override;

private:
    // One listed problem with a profile file.
    struct Row {
        enum class Kind { Error, NeedsNorm };
        std::string file;        // full path
        Kind        kind = Kind::Error;
        std::string detail;      // parser error output, or the normalization diff
        std::string normalized;  // normalized text to write (NeedsNorm only)
    };

    void onValidate(wxCommandEvent&);
    void onNormalize(wxCommandEvent&);
    void onItemSelected(wxListEvent&);
    void onPoll(wxTimerEvent&);

    void startValidation();
    void finishValidation();
    void updateNormalizeButton();

    class ErrorList;
    wxString OnGetItemText(long item, long column) const;

    ProfilesProvider m_profiles;
    ReloadProfiles   m_reloadProfiles;

    wxButton*     m_validateBtn  = nullptr;
    wxButton*     m_normalizeBtn = nullptr;
    wxStaticText* m_summary      = nullptr;
    ErrorList*    m_list         = nullptr;
    wxTextCtrl*   m_detail       = nullptr;
    wxTimer       m_timer;

    std::vector<Row> m_rows;     // shown in the list
    long             m_selected = -1;

    // Worker state. m_results is written by the worker thread under m_mutex.
    std::thread            m_worker;
    std::mutex             m_mutex;
    std::vector<Row>       m_results; // guarded by m_mutex
    std::atomic<std::size_t> m_done{0};
    std::atomic<bool>        m_finished{false};
    std::atomic<bool>        m_cancel{false};
    std::size_t              m_total = 0;

    wxDECLARE_EVENT_TABLE();
};
