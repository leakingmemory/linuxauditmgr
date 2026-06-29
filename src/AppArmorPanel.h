#pragma once

#include <set>
#include <string>
#include <vector>

#include <wx/wx.h>
#include <wx/listctrl.h>

#include "AppArmorParser.h"

// Notebook page that loads a directory of AppArmor profiles and shows, per
// profile, what access it gives (allow rules) and takes away (deny rules).
class AppArmorPanel : public wxPanel {
public:
    AppArmorPanel(wxWindow* parent, const wxString& initialDir);

    // The most recently parsed profiles (for cross-referencing, e.g. denials).
    const apparmor::ParseResult& result() const { return m_result; }

    // Re-parse the currently selected directory (e.g. after an external edit).
    void reload();

private:
    void onBrowse(wxCommandEvent&);
    void onReload(wxCommandEvent&);
    void onFilterChanged(wxCommandEvent&);
    void onItemSelected(wxListEvent&);
    void onSetEnforce(wxCommandEvent&);
    void onSetComplain(wxCommandEvent&);
    void onToggleDisable(wxCommandEvent&);

    void loadDir(const wxString& dir);
    void rebuildFilter();
    bool matches(const apparmor::Profile& p) const;
    wxString detailFor(const apparmor::Profile& p) const;

    // Enable/disable the mode buttons and set the disable button's label for the
    // current selection.
    void updateModeButtons();
    // True when the currently loaded profile file of the selection is disabled.
    bool selectionDisabled() const;
    // Apply a complain/enforce edit (and, when possible, reload) to the
    // selected profile; `complain` picks the target mode.
    void applyComplainMode(bool complain);

    // The list shows top-level profiles and their nested children flattened,
    // each row pointing back at its Profile.
    struct Row {
        const apparmor::Profile* prof = nullptr;
        int depth = 0;
    };
    void flatten(const apparmor::Profile& p, int depth);

    class ProfileList;
    wxString OnGetItemText(long item, long column) const;

    wxTextCtrl* m_dirCtrl    = nullptr;
    wxTextCtrl* m_searchCtrl = nullptr;
    ProfileList* m_list      = nullptr;
    wxTextCtrl* m_detail     = nullptr;
    wxButton*   m_enforceBtn = nullptr;
    wxButton*   m_complainBtn = nullptr;
    wxButton*   m_disableBtn = nullptr;

    apparmor::ParseResult     m_result;
    std::vector<Row>          m_rows;      // all profiles, flattened
    std::vector<std::size_t>  m_filtered;  // indices into m_rows

    // The directory the current m_result was parsed from (where reloads, flag
    // edits and disable symlinks act).
    std::string               m_loadedDir;
    // Source files that have a boot-time disable symlink, shown as "disabled".
    std::set<std::string>     m_disabledFiles;

    // The selected profile, captured as plain strings so it survives a reparse
    // (the Row pointers into m_result do not). Empty name => no selection.
    std::string               m_selName;
    std::string               m_selFile;

    wxDECLARE_EVENT_TABLE();
};
