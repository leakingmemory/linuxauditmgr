#pragma once

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

private:
    void onBrowse(wxCommandEvent&);
    void onReload(wxCommandEvent&);
    void onFilterChanged(wxCommandEvent&);
    void onItemSelected(wxListEvent&);

    void loadDir(const wxString& dir);
    void rebuildFilter();
    bool matches(const apparmor::Profile& p) const;
    wxString detailFor(const apparmor::Profile& p) const;

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

    apparmor::ParseResult     m_result;
    std::vector<Row>          m_rows;      // all profiles, flattened
    std::vector<std::size_t>  m_filtered;  // indices into m_rows

    wxDECLARE_EVENT_TABLE();
};
