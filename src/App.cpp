#include <wx/wx.h>
#include <wx/filename.h>

#include "MainFrame.h"

// Entry point. Picks a sensible default log path: the system audit log if it
// is readable, otherwise a sample audit.log in the working directory.
class AuditMgrApp : public wxApp {
public:
    bool OnInit() override {
        wxString path = "/var/log/audit/audit.log";
        if (!wxFileName::IsFileReadable(path)) {
            if (wxFileName::IsFileReadable("audit.log"))
                path = wxFileName("audit.log").GetAbsolutePath();
        }

        auto* frame = new MainFrame(path);
        frame->Show(true);
        return true;
    }
};

wxIMPLEMENT_APP(AuditMgrApp);
