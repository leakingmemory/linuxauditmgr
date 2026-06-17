#pragma once

#include <vector>

#include <wx/wx.h>
#include <wx/listctrl.h>

#include "AuditParser.h"
#include "LogTailer.h"

// Main application window: controls to load / live-follow an audit log, a
// virtual list of decoded events, and a detail pane for the selected event.
class MainFrame : public wxFrame {
public:
    explicit MainFrame(const wxString& initialPath);
    ~MainFrame() override;

private:
    // Virtual list callbacks.
    wxString OnGetItemText(long item, long column) const;

    // UI event handlers.
    void onBrowse(wxCommandEvent&);
    void onReadCurrent(wxCommandEvent&);
    void onStartLive(wxCommandEvent&);
    void onStopLive(wxCommandEvent&);
    void onFilterChanged(wxCommandEvent&);
    void onItemSelected(wxListEvent&);

    // Worker -> UI marshalling.
    void appendEvents(std::vector<audit::Event> events, bool reset);
    void setStatus(const std::string& text);

    void rebuildFilter();
    bool matchesFilter(const audit::Event& ev) const;
    void refreshTypeChoices();
    void updateButtons();

    // A small wxListCtrl subclass that forwards virtual text requests here.
    class EventList;

    wxTextCtrl*  m_pathCtrl     = nullptr;
    wxButton*    m_readBtn      = nullptr;
    wxButton*    m_liveBtn      = nullptr;
    wxButton*    m_stopBtn      = nullptr;
    wxTextCtrl*  m_searchCtrl   = nullptr;
    wxChoice*    m_typeChoice   = nullptr;
    EventList*   m_list         = nullptr;
    wxTextCtrl*  m_detail       = nullptr;

    std::vector<audit::Event> m_events;     // all loaded events
    std::vector<std::size_t>  m_filtered;   // indices into m_events that match

    LogTailer m_tailer;
    bool      m_live = false;

    wxDECLARE_EVENT_TABLE();
};
