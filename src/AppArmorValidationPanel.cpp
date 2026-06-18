#include "AppArmorValidationPanel.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

#include <wx/msgdlg.h>
#include <wx/splitter.h>

#include "AppArmorEditor.h"
#include "AppArmorNormalizer.h"
#include "AppArmorParser.h"
#include "AppArmorValidator.h"

namespace {
enum {
    ID_ValButton = wxID_HIGHEST + 300,
    ID_ValNormalize,
    ID_ValList,
    ID_ValTimer,
};

constexpr int kColFile = 0;
constexpr int kColStatus = 1;
constexpr int kColDetail = 2;

wxString firstLine(const std::string& s) {
    const std::size_t nl = s.find('\n');
    return wxString::FromUTF8(nl == std::string::npos ? s : s.substr(0, nl));
}

std::string readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Collect every loaded profile's name and attachment (children too), so the
// normalizer can recognise a peer= label that refers to a real profile and
// repair it if its glob metacharacters were left unescaped.
void collectProfileNames(const std::vector<apparmor::Profile>& profiles,
                         std::set<std::string>& out) {
    for (const auto& p : profiles) {
        if (!p.name.empty())
            out.insert(p.name);
        if (!p.attachment.empty())
            out.insert(p.attachment);
        collectProfileNames(p.children, out);
    }
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
    EVT_BUTTON(ID_ValNormalize, AppArmorValidationPanel::onNormalize)
    EVT_LIST_ITEM_SELECTED(ID_ValList, AppArmorValidationPanel::onItemSelected)
    EVT_TIMER(ID_ValTimer, AppArmorValidationPanel::onPoll)
wxEND_EVENT_TABLE()

AppArmorValidationPanel::AppArmorValidationPanel(wxWindow* parent,
                                                 ProfilesProvider profiles,
                                                 ReloadProfiles reload)
    : wxPanel(parent), m_profiles(std::move(profiles)),
      m_reloadProfiles(std::move(reload)) {
    m_timer.SetOwner(this, ID_ValTimer);

    auto* sizer = new wxBoxSizer(wxVERTICAL);

    auto* topRow = new wxBoxSizer(wxHORIZONTAL);
    m_summary = new wxStaticText(
        this, wxID_ANY,
        "Validate the profile files in the loaded directory with "
        "apparmor_parser, and flag ones that fail or need normalizing.");
    topRow->Add(m_summary, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 8);
    m_normalizeBtn = new wxButton(this, ID_ValNormalize, "Normalize selected...");
    m_normalizeBtn->Enable(false);
    topRow->Add(m_normalizeBtn, 0, wxRIGHT, 6);
    m_validateBtn = new wxButton(this, ID_ValButton, "Validate profiles");
    topRow->Add(m_validateBtn, 0);
    sizer->Add(topRow, 0, wxEXPAND | wxALL, 8);

    auto* splitter = new wxSplitterWindow(this, wxID_ANY);
    splitter->SetMinimumPaneSize(120);

    m_list = new ErrorList(this, splitter);
    m_list->AppendColumn("Profile file", wxLIST_FORMAT_LEFT, 320);
    m_list->AppendColumn("Status", wxLIST_FORMAT_LEFT, 150);
    m_list->AppendColumn("Detail", wxLIST_FORMAT_LEFT, 660);

    m_detail = new wxTextCtrl(splitter, wxID_ANY, "", wxDefaultPosition,
                              wxDefaultSize,
                              wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    m_detail->SetFont(wxFont(wxFontInfo(10).Family(wxFONTFAMILY_TELETYPE)));

    splitter->SplitHorizontally(m_list, m_detail, 300);
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
        return;
    if (!apparmor::validatorAvailable()) {
        wxMessageBox("apparmor_parser was not found, so profiles cannot be "
                     "validated. Install the AppArmor userspace tools.",
                     "Validation", wxOK | wxICON_ERROR, this);
        return;
    }
    if (!m_profiles || m_profiles().directory.empty()) {
        wxMessageBox("Load a profiles directory in the Profiles sub-tab first.",
                     "Validation", wxOK | wxICON_INFORMATION, this);
        return;
    }
    startValidation();
}

void AppArmorValidationPanel::startValidation() {
    std::vector<std::string> files =
        apparmor::listProfileFiles(m_profiles().directory);
    if (files.empty()) {
        wxMessageBox("No profile files found in " +
                         wxString::FromUTF8(m_profiles().directory),
                     "Validation", wxOK | wxICON_INFORMATION, this);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_results.clear();
    }
    m_rows.clear();
    m_selected = -1;
    m_list->SetItemCount(0);
    m_list->Refresh();
    m_detail->Clear();
    m_done = 0;
    m_finished = false;
    m_cancel = false;
    m_total = files.size();

    // Snapshot the loaded profile names on the UI thread; the worker uses them
    // to recognise (and repair) peer= labels that refer to a real profile.
    std::set<std::string> knownNames;
    collectProfileNames(m_profiles().profiles, knownNames);

    m_validateBtn->Enable(false);
    m_normalizeBtn->Enable(false);
    m_summary->SetLabel(wxString::Format("Validating 0/%zu ...", m_total));

    m_worker = std::thread([this, files = std::move(files),
                            knownNames = std::move(knownNames)] {
        for (const auto& file : files) {
            if (m_cancel)
                break;
            apparmor::ValidationResult v = apparmor::validateProfile(file);
            Row row;
            row.file = file;
            if (!v.ok) {
                row.kind = Row::Kind::Error;
                row.detail = v.output;
            } else {
                auto n = apparmor::normalizeProfileText(readFile(file),
                                                        knownNames);
                if (!n.changed) {
                    ++m_done;
                    continue; // clean and canonical: nothing to report
                }
                row.kind = Row::Kind::NeedsNorm;
                row.detail = n.diff;
                row.normalized = std::move(n.normalized);
            }
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_results.push_back(std::move(row));
            }
            ++m_done;
        }
        m_finished = true;
    });

    m_timer.Start(150);
}

void AppArmorValidationPanel::onPoll(wxTimerEvent&) {
    if (!m_finished.load()) {
        m_summary->SetLabel(
            wxString::Format("Validating %zu/%zu ...", m_done.load(), m_total));
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
        m_rows = std::move(m_results);
        m_results.clear();
    }
    std::sort(m_rows.begin(), m_rows.end(),
              [](const Row& a, const Row& b) {
                  if (a.kind != b.kind)
                      return a.kind < b.kind; // errors first
                  return a.file < b.file;
              });

    std::size_t errors = 0, norm = 0;
    for (const auto& r : m_rows)
        (r.kind == Row::Kind::Error ? errors : norm)++;

    m_list->SetItemCount(static_cast<long>(m_rows.size()));
    m_list->Refresh();
    m_selected = -1;
    updateNormalizeButton();

    if (m_rows.empty()) {
        m_summary->SetLabel(wxString::Format(
            "All %zu profiles are valid and canonical.", m_total));
        m_detail->SetValue("Nothing to fix.");
    } else {
        m_summary->SetLabel(wxString::Format(
            "%zu profiles  -  %zu with errors, %zu need normalization.",
            m_total, errors, norm));
        m_detail->SetValue("Select a profile: errors show the apparmor_parser "
                           "output; normalizable ones show the diff that "
                           "Normalize would apply.");
    }
    m_validateBtn->Enable(true);
}

void AppArmorValidationPanel::updateNormalizeButton() {
    const bool can = m_selected >= 0 &&
                     static_cast<std::size_t>(m_selected) < m_rows.size() &&
                     m_rows[m_selected].kind == Row::Kind::NeedsNorm;
    m_normalizeBtn->Enable(can);
}

void AppArmorValidationPanel::onItemSelected(wxListEvent& evt) {
    long row = evt.GetIndex();
    if (row < 0 || static_cast<std::size_t>(row) >= m_rows.size())
        return;
    m_selected = row;
    const Row& r = m_rows[row];
    if (r.kind == Row::Kind::Error)
        m_detail->SetValue(wxString::FromUTF8(r.file) + "\n\n" +
                           wxString::FromUTF8(r.detail));
    else
        m_detail->SetValue(
            wxString::FromUTF8(r.file) +
            "\n\nNormalization would apply this diff "
            "(- removed, + added; body comments are dropped):\n\n" +
            wxString::FromUTF8(r.detail));
    updateNormalizeButton();
}

void AppArmorValidationPanel::onNormalize(wxCommandEvent&) {
    if (m_selected < 0 || static_cast<std::size_t>(m_selected) >= m_rows.size())
        return;
    const Row row = m_rows[m_selected]; // copy; m_rows is rebuilt after
    if (row.kind != Row::Kind::NeedsNorm)
        return;

    wxString msg = "Apply normalization to:\n    " +
                   wxString::FromUTF8(row.file) +
                   "\n\nThe diff shown in the detail pane will be written "
                   "(crash-safely). Comments inside the profile body are "
                   "removed. The result is re-checked with apparmor_parser "
                   "before replacing the file.";
    wxMessageDialog confirm(this, msg, "Confirm normalization",
                            wxYES_NO | wxICON_QUESTION);
    confirm.SetYesNoLabels("&Write normalized", "&Cancel");
    if (confirm.ShowModal() != wxID_YES)
        return;

    // Re-check the normalized text with apparmor_parser via a temp file before
    // committing, so we never write a normalization that fails to compile.
    const std::filesystem::path tmp =
        std::filesystem::path(row.file).string() + ".aanormcheck." +
        std::to_string(::getpid());
    {
        std::string err;
        if (!apparmor::writeFileAtomically(tmp.string(), row.normalized, err)) {
            wxMessageBox("Could not write a temp file to validate: " +
                             wxString::FromUTF8(err),
                         "Normalization failed", wxOK | wxICON_ERROR, this);
            return;
        }
    }
    apparmor::ValidationResult v = apparmor::validateProfile(tmp.string());
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    if (!v.ok) {
        wxMessageBox("The normalized profile did not pass apparmor_parser, so "
                     "it was NOT written:\n\n" + wxString::FromUTF8(v.output),
                     "Normalization failed", wxOK | wxICON_ERROR, this);
        return;
    }

    std::string err;
    if (!apparmor::writeFileAtomically(row.file, row.normalized, err)) {
        wxMessageBox(wxString::FromUTF8(err), "Normalization failed",
                     wxOK | wxICON_ERROR, this);
        return;
    }

    wxMessageBox("Normalized " +
                     wxString::FromUTF8(
                         std::filesystem::path(row.file).filename().string()) +
                     ".\nReload it into the kernel with `apparmor_parser -r` to "
                     "apply (no semantic change).",
                 "Normalization", wxOK | wxICON_INFORMATION, this);

    if (m_reloadProfiles)
        m_reloadProfiles();
    // Re-run validation so the list reflects the change.
    wxCommandEvent dummy;
    onValidate(dummy);
}

wxString AppArmorValidationPanel::OnGetItemText(long item, long column) const {
    if (item < 0 || static_cast<std::size_t>(item) >= m_rows.size())
        return {};
    const Row& r = m_rows[item];
    switch (column) {
    case kColFile:
        return wxString::FromUTF8(
            std::filesystem::path(r.file).filename().string());
    case kColStatus:
        return r.kind == Row::Kind::Error ? "error" : "needs normalization";
    case kColDetail:
        return r.kind == Row::Kind::Error
                   ? firstLine(r.detail)
                   : "rules can be sorted / merged / de-duplicated";
    default:
        return {};
    }
}
