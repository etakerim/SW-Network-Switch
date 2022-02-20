#ifndef SWITCH_HPP
#define SWITCH_HPP

#include <wx/wx.h>

class App : public wxApp 
{
public:
    virtual bool OnInit();
};

wxIMPLEMENT_APP(App);


class DeviceWindow: public wxFrame 
{
public:
    DeviceWindow();
private:
    void camTablePage(wxPanel* page);
    void statisticsPage(wxPanel* page);
    void filtersPage(wxPanel* page);
    void syslogPage(wxPanel* page);

    void clearMACTable(wxCommandEvent& event);
    void setMACTimeout(wxCommandEvent& event);
    
    void resetTrafficStats(wxCommandEvent& event);
    
    void addTrafficFilter(wxCommandEvent& event);
    void deleteTrafficFilter(wxCommandEvent& event);
    void deleteAllTrafficFilters(wxCommandEvent& event);

    void manageSyslogService(wxCommandEvent& event);
    void clearSyslogConsole(wxCommandEvent& event);
};

#endif
