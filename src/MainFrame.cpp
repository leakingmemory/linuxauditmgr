#include "MainFrame.h"

#include <algorithm>
#include <cctype>

#include <wx/filedlg.h>
#include <wx/notebook.h>
#include <wx/splitter.h>

#include "AppArmorTab.h"

namespace {
enum {
    ID_Browse = wxID_HIGHEST + 1,
    ID_ReadCurrent,
    ID_StartLive,
    ID_StopLive,
    ID_Search,
    ID_TypeChoice,
    ID_List,
};

constexpr int kColTime = 0;
constexpr int kColSerial = 1;
constexpr int kColTypes = 2;
constexpr int kColPid = 3;
constexpr int kColComm = 4;
constexpr int kColSummary = 5;

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

// Default directory for the AppArmor tab: the system location, so reads,
// writes and reapplies act on the profiles the kernel actually loads. The
// LINUXAUDITMGR_APPARMOR_DIR environment variable overrides it, which is handy
// for testing against a readable copy (e.g. ~/apparmor.d) without root.
wxString defaultAppArmorDir() {
    if (wxString override; wxGetEnv("LINUXAUDITMGR_APPARMOR_DIR", &override) &&
                           !override.empty())
        return override;
    return "/etc/apparmor.d";
}
} // namespace

// Virtual list control: text is supplied on demand so we can show thousands
// of events without populating per-row data.
class MainFrame::EventList : public wxListCtrl {
public:
    EventList(MainFrame* owner, wxWindow* parent)
        : wxListCtrl(parent, ID_List, wxDefaultPosition, wxDefaultSize,
                     wxLC_REPORT | wxLC_VIRTUAL | wxLC_SINGLE_SEL),
          m_owner(owner) {}

protected:
    wxString OnGetItemText(long item, long column) const override {
        return m_owner->OnGetItemText(item, column);
    }

private:
    MainFrame* m_owner;
};

wxBEGIN_EVENT_TABLE(MainFrame, wxFrame)
    EVT_BUTTON(ID_Browse, MainFrame::onBrowse)
    EVT_BUTTON(ID_ReadCurrent, MainFrame::onReadCurrent)
    EVT_BUTTON(ID_StartLive, MainFrame::onStartLive)
    EVT_BUTTON(ID_StopLive, MainFrame::onStopLive)
    EVT_TEXT(ID_Search, MainFrame::onFilterChanged)
    EVT_CHOICE(ID_TypeChoice, MainFrame::onFilterChanged)
    EVT_LIST_ITEM_SELECTED(ID_List, MainFrame::onItemSelected)
wxEND_EVENT_TABLE()

MainFrame::MainFrame(const wxString& initialPath)
    : wxFrame(nullptr, wxID_ANY, "Linux Audit Manager",
              wxDefaultPosition, wxSize(1100, 720)) {

    auto* notebook = new wxNotebook(this, wxID_ANY);

    // --- Page 1: the audit log viewer (built on its own panel) ---
    auto* root = new wxPanel(notebook);
    auto* rootSizer = new wxBoxSizer(wxVERTICAL);

    // --- Row 1: file path + browse ---
    auto* pathRow = new wxBoxSizer(wxHORIZONTAL);
    pathRow->Add(new wxStaticText(root, wxID_ANY, "Log file:"), 0,
                 wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    m_pathCtrl = new wxTextCtrl(root, wxID_ANY, initialPath);
    pathRow->Add(m_pathCtrl, 1, wxALIGN_CENTER_VERTICAL | wxRIGHT, 6);
    auto* browseBtn = new wxButton(root, ID_Browse, "Browse…");
    pathRow->Add(browseBtn, 0);
    rootSizer->Add(pathRow, 0, wxEXPAND | wxALL, 8);

    // --- Row 2: action buttons + filters ---
    auto* actionRow = new wxBoxSizer(wxHORIZONTAL);
    m_readBtn = new wxButton(root, ID_ReadCurrent, "Read Current Logs");
    m_liveBtn = new wxButton(root, ID_StartLive, "Start Live");
    m_stopBtn = new wxButton(root, ID_StopLive, "Stop Live");
    actionRow->Add(m_readBtn, 0, wxRIGHT, 6);
    actionRow->Add(m_liveBtn, 0, wxRIGHT, 6);
    actionRow->Add(m_stopBtn, 0, wxRIGHT, 16);

    actionRow->Add(new wxStaticText(root, wxID_ANY, "Type:"), 0,
                   wxALIGN_CENTER_VERTICAL | wxRIGHT, 4);
    m_typeChoice = new wxChoice(root, ID_TypeChoice);
    actionRow->Add(m_typeChoice, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, 16);

    actionRow->Add(new wxStaticText(root, wxID_ANY, "Filter:"), 0,
                   wxALIGN_CENTER_VERTICAL | wxRIGHT, 4);
    m_searchCtrl = new wxTextCtrl(root, ID_Search, "", wxDefaultPosition,
                                  wxDefaultSize, wxTE_PROCESS_ENTER);
    m_searchCtrl->SetHint("substring match…");
    actionRow->Add(m_searchCtrl, 1, wxALIGN_CENTER_VERTICAL);
    rootSizer->Add(actionRow, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    // --- Splitter: event list (top) + detail (bottom) ---
    auto* splitter = new wxSplitterWindow(root, wxID_ANY);
    splitter->SetMinimumPaneSize(120);

    m_list = new EventList(this, splitter);
    m_list->AppendColumn("Time", wxLIST_FORMAT_LEFT, 175);
    m_list->AppendColumn("Event", wxLIST_FORMAT_RIGHT, 80);
    m_list->AppendColumn("Types", wxLIST_FORMAT_LEFT, 180);
    m_list->AppendColumn("PID", wxLIST_FORMAT_RIGHT, 70);
    m_list->AppendColumn("Comm", wxLIST_FORMAT_LEFT, 130);
    m_list->AppendColumn("Summary", wxLIST_FORMAT_LEFT, 440);

    m_detail = new wxTextCtrl(splitter, wxID_ANY, "", wxDefaultPosition,
                              wxDefaultSize,
                              wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    m_detail->SetFont(wxFont(wxFontInfo(10).Family(wxFONTFAMILY_TELETYPE)));

    splitter->SplitHorizontally(m_list, m_detail, 440);
    rootSizer->Add(splitter, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, 8);

    root->SetSizer(rootSizer);

    // --- Page 2: AppArmor (profiles + denials sub-tabs) ---
    auto* apparmor = new AppArmorTab(
        notebook, defaultAppArmorDir(),
        [this]() -> const std::vector<audit::Event>& { return m_events; });

    notebook->AddPage(root, "Audit Log");
    notebook->AddPage(apparmor, "AppArmor");

    CreateStatusBar();
    SetStatusText("Ready. Choose a log file, then Read Current Logs or Start Live.");

    m_typeChoice->Append("All types");
    m_typeChoice->SetSelection(0);

    m_tailer.setCallbacks(
        [this](std::vector<audit::Event> evs, bool reset) {
            // Worker thread → marshal onto the UI thread.
            CallAfter([this, evs = std::move(evs), reset]() mutable {
                appendEvents(std::move(evs), reset);
            });
        },
        [this](const std::string& text) {
            CallAfter([this, text]() { setStatus(text); });
        });

    updateButtons();
}

MainFrame::~MainFrame() {
    m_tailer.stop();
}

void MainFrame::updateButtons() {
    m_stopBtn->Enable(m_live);
    m_liveBtn->Enable(!m_live);
    m_readBtn->Enable(!m_live);
}

void MainFrame::onBrowse(wxCommandEvent&) {
    wxFileDialog dlg(this, "Open audit log", "", m_pathCtrl->GetValue(),
                     "Log files (*.log)|*.log|All files (*.*)|*.*",
                     wxFD_OPEN | wxFD_FILE_MUST_EXIST);
    if (dlg.ShowModal() == wxID_OK)
        m_pathCtrl->SetValue(dlg.GetPath());
}

void MainFrame::onReadCurrent(wxCommandEvent&) {
    m_tailer.stop();
    m_live = false;
    updateButtons();
    SetStatusText("Reading " + m_pathCtrl->GetValue() + " …");
    m_tailer.readAll(m_pathCtrl->GetValue().ToStdString());
}

void MainFrame::onStartLive(wxCommandEvent&) {
    m_tailer.stop();
    m_live = true;
    updateButtons();
    SetStatusText("Starting live follow of " + m_pathCtrl->GetValue() + " …");
    m_tailer.startLive(m_pathCtrl->GetValue().ToStdString());
}

void MainFrame::onStopLive(wxCommandEvent&) {
    m_tailer.stop();
    m_live = false;
    updateButtons();
    SetStatusText("Live follow stopped.");
}

void MainFrame::setStatus(const std::string& text) {
    SetStatusText(text);
}

void MainFrame::appendEvents(std::vector<audit::Event> events, bool reset) {
    if (reset) {
        m_events.clear();
        m_filtered.clear();
        m_typeChoice->SetSelection(0);
    }

    const std::size_t firstNew = m_events.size();
    m_events.insert(m_events.end(),
                    std::make_move_iterator(events.begin()),
                    std::make_move_iterator(events.end()));

    // Incrementally extend the filtered view rather than rebuilding it all.
    for (std::size_t i = firstNew; i < m_events.size(); ++i)
        if (matchesFilter(m_events[i]))
            m_filtered.push_back(i);

    refreshTypeChoices();
    m_list->SetItemCount(static_cast<long>(m_filtered.size()));
    m_list->Refresh();

    if (m_live && !m_filtered.empty())
        m_list->EnsureVisible(static_cast<long>(m_filtered.size()) - 1);

    if (!m_live)
        SetStatusText(wxString::Format("%zu events (%zu shown)",
                                       m_events.size(), m_filtered.size()));
}

void MainFrame::refreshTypeChoices() {
    // Collect the set of record types currently present and add any missing
    // ones to the choice control (preserving the current selection).
    wxString current = m_typeChoice->GetStringSelection();
    std::vector<wxString> wanted;
    for (const auto& ev : m_events)
        for (const auto& r : ev.records) {
            wxString t(r.type);
            if (m_typeChoice->FindString(t) == wxNOT_FOUND &&
                std::find(wanted.begin(), wanted.end(), t) == wanted.end())
                wanted.push_back(t);
        }
    if (wanted.empty())
        return;
    std::sort(wanted.begin(), wanted.end());
    for (const auto& t : wanted)
        m_typeChoice->Append(t);
    int sel = m_typeChoice->FindString(current);
    m_typeChoice->SetSelection(sel == wxNOT_FOUND ? 0 : sel);
}

bool MainFrame::matchesFilter(const audit::Event& ev) const {
    // Type filter.
    if (m_typeChoice->GetSelection() > 0) {
        const std::string want = m_typeChoice->GetStringSelection().ToStdString();
        bool hit = false;
        for (const auto& r : ev.records)
            if (r.type == want) { hit = true; break; }
        if (!hit)
            return false;
    }

    // Text filter (case-insensitive substring over the human-readable view).
    wxString needleRaw = m_searchCtrl ? m_searchCtrl->GetValue() : wxString();
    if (needleRaw.empty())
        return true;
    const std::string needle = toLower(needleRaw.ToStdString());

    std::string hay = toLower(ev.summary() + " " + ev.typesJoined() + " " +
                              ev.comm() + " " + ev.exe() + " " + ev.pid());
    if (hay.find(needle) != std::string::npos)
        return true;
    // Also search the raw record text so nothing is hidden.
    for (const auto& r : ev.records)
        if (toLower(r.raw).find(needle) != std::string::npos)
            return true;
    return false;
}

void MainFrame::rebuildFilter() {
    m_filtered.clear();
    for (std::size_t i = 0; i < m_events.size(); ++i)
        if (matchesFilter(m_events[i]))
            m_filtered.push_back(i);
    m_list->SetItemCount(static_cast<long>(m_filtered.size()));
    m_list->Refresh();
    SetStatusText(wxString::Format("%zu events (%zu shown)",
                                   m_events.size(), m_filtered.size()));
}

void MainFrame::onFilterChanged(wxCommandEvent&) {
    rebuildFilter();
}

void MainFrame::onItemSelected(wxListEvent& evt) {
    long row = evt.GetIndex();
    if (row < 0 || static_cast<std::size_t>(row) >= m_filtered.size())
        return;
    const audit::Event& ev = m_events[m_filtered[row]];
    m_detail->SetValue(ev.detail());
}

wxString MainFrame::OnGetItemText(long item, long column) const {
    if (item < 0 || static_cast<std::size_t>(item) >= m_filtered.size())
        return {};
    const audit::Event& ev = m_events[m_filtered[item]];
    switch (column) {
    case kColTime:    return wxString::FromUTF8(ev.formattedTime());
    case kColSerial:  return wxString::Format("%lld", static_cast<long long>(ev.serial));
    case kColTypes:   return wxString::FromUTF8(ev.typesJoined());
    case kColPid:     return wxString::FromUTF8(ev.pid());
    case kColComm:    return wxString::FromUTF8(ev.comm());
    case kColSummary: return wxString::FromUTF8(ev.summary());
    default:          return {};
    }
}
