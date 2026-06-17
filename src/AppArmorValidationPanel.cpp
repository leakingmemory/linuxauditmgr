#include "AppArmorValidationPanel.h"

#include <algorithm>
#include <filesystem>

#include <wx/msgdlg.h>
#include <wx/splitter.h>

namespace {
enum {
    ID_ValButton = wxID_HIGHEST + 300,
    ID_ValList,
    ID_ValTimer,
};

constexpr int kColFile = 0;
constexpr int kColError = 1;

// The first non-empty line of the parser output, for the list's Error column.
wxString firstLine(const std::string& s) {
    const std::size_t nl = s.find('\n');
    return wxString::FromUTF8(nl == std::string::npos ? s : s.substr(0, nl));
}
} // namespace

class AppArmorValidationPanel::ErrorList : public wxListCtrl {
public:
    ErrorList(AppArmorValidationPanel* owner, wxWindow* parent)
        : wxListCtrl(parent, ID_ValList, wxDefaultPosition, wxDefaultSize,
                     wxLC_REPORT | wxLC_VIRTUAL | wxLC_SINGLE_SEL),
          m_owner(owner) {}

protected:
    wxString OnGetItemText(long item, long column) const override {
        return m_owner->OnGetItemText(item, column);
    }

private:
    AppArmorValidationPanel* m_owner;
};

wxBEGIN_EVENT_TABLE(AppArmorValidationPanel, wxPanel)
    EVT_BUTTON(ID_ValButton, AppArmorValidationPanel::onValidate)
    EVT_LIST_ITEM_SELECTED(ID_ValList, AppArmorValidationPanel::onItemSelected)
    EVT_TIMER(ID_ValTimer, AppArmorValidationPanel::onPoll)
wxEND_EVENT_TABLE()

AppArmorValidationPanel::AppArmorValidationPanel(wxWindow* parent,
                                                 ProfilesProvider profiles)
    : wxPanel(parent), m_profiles(std::move(profiles)) {
    m_timer.SetOwner(this, ID_ValTimer);

    auto* sizer = new wxBoxSizer(wxVERTICAL);

    auto* topRow = new wxBoxSizer(wxHORIZONTAL);
    m_summary = new wxStaticText(
        this, wxID_ANY,
        "Validate the profile files in the loaded directory with "
        "apparmor_parser, and list the ones that fail.");
    topRow->Add(m_summary, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);
    m_validateBtn = new wxButton(this, ID_ValButton, "Validate profiles");
    topRow->Add(m_validateBtn, 0);
    sizer->Add(topRow, 0, wxEXPAND | wxALL, 8);

    auto* splitter = new wxSplitterWindow(this, wxID_ANY);
    splitter->SetMinimumPaneSize(120);

    m_list = new ErrorList(this, splitter);
    m_list->AppendColumn("Profile file", wxLIST_FORMAT_LEFT, 360);
    m_list->AppendColumn("Error", wxLIST_FORMAT_LEFT, 780);

    m_detail = new wxTextCtrl(splitter, wxID_ANY, "", wxDefaultPosition,
                              wxDefaultSize,
                              wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    m_detail->SetFont(wxFont(wxFontInfo(10).Family(wxFONTFAMILY_TELETYPE)));

    splitter->SplitHorizontally(m_list, m_detail, 320);
    sizer->Add(splitter, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    SetSizer(sizer);
}

AppArmorValidationPanel::~AppArmorValidationPanel() {
    m_timer.Stop();
    m_cancel = true;
    if (m_worker.joinable())
        m_worker.join();
}

void AppArmorValidationPanel::onValidate(wxCommandEvent&) {
    if (m_worker.joinable())
        return; // already validating

    if (!apparmor::validatorAvailable()) {
        wxMessageBox("apparmor_parser was not found, so profiles cannot be "
                     "validated. Install the AppArmor userspace tools.",
                     "Validation", wxOK | wxICON_ERROR, this);
        return;
    }

    const std::string dir =
        m_profiles ? m_profiles().directory : std::string();
    if (dir.empty()) {
        wxMessageBox("Load a profiles directory in the Profiles sub-tab first.",
                     "Validation", wxOK | wxICON_INFORMATION, this);
        return;
    }
    startValidation();
}

void AppArmorValidationPanel::startValidation() {
    const std::string dir = m_profiles().directory;
    std::vector<std::string> files = apparmor::listProfileFiles(dir);
    if (files.empty()) {
        wxMessageBox("No profile files found in " + wxString::FromUTF8(dir),
                     "Validation", wxOK | wxICON_INFORMATION, this);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_results.clear();
    }
    m_failures.clear();
    m_list->SetItemCount(0);
    m_list->Refresh();
    m_detail->Clear();
    m_done = 0;
    m_finished = false;
    m_cancel = false;
    m_total = files.size();

    m_validateBtn->Enable(false);
    m_summary->SetLabel(wxString::Format("Validating 0/%zu ...", m_total));

    m_worker = std::thread([this, files = std::move(files)] {
        for (const auto& file : files) {
            if (m_cancel)
                break;
            apparmor::ValidationResult r = apparmor::validateProfile(file);
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_results.push_back(std::move(r));
            }
            ++m_done;
        }
        m_finished = true;
    });

    m_timer.Start(150);
}

void AppArmorValidationPanel::onPoll(wxTimerEvent&) {
    const std::size_t done = m_done.load();
    if (!m_finished.load()) {
        m_summary->SetLabel(
            wxString::Format("Validating %zu/%zu ...", done, m_total));
        return;
    }
    m_timer.Stop();
    if (m_worker.joinable())
        m_worker.join();
    finishValidation();
}

void AppArmorValidationPanel::finishValidation() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_failures.clear();
        for (const auto& r : m_results)
            if (!r.ok)
                m_failures.push_back(r);
    }
    std::sort(m_failures.begin(), m_failures.end(),
              [](const auto& a, const auto& b) { return a.file < b.file; });

    m_list->SetItemCount(static_cast<long>(m_failures.size()));
    m_list->Refresh();

    if (m_failures.empty()) {
        m_summary->SetLabel(wxString::Format(
            "All %zu profiles validated cleanly.", m_total));
        m_detail->SetValue("No profiles failed validation.");
    } else {
        m_summary->SetLabel(wxString::Format(
            "%zu profiles validated  -  %zu with errors.", m_total,
            m_failures.size()));
        m_detail->SetValue("Select a profile to see the full apparmor_parser "
                           "error output.");
    }
    m_validateBtn->Enable(true);
}

void AppArmorValidationPanel::onItemSelected(wxListEvent& evt) {
    long row = evt.GetIndex();
    if (row < 0 || static_cast<std::size_t>(row) >= m_failures.size())
        return;
    const auto& r = m_failures[row];
    m_detail->SetValue(wxString::FromUTF8(r.file) + "\n\n" +
                       wxString::FromUTF8(r.output));
}

wxString AppArmorValidationPanel::OnGetItemText(long item, long column) const {
    if (item < 0 || static_cast<std::size_t>(item) >= m_failures.size())
        return {};
    const auto& r = m_failures[item];
    switch (column) {
    case kColFile:
        return wxString::FromUTF8(std::filesystem::path(r.file).filename().string());
    case kColError:
        return firstLine(r.output);
    default:
        return {};
    }
}
