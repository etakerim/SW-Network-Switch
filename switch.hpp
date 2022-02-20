#ifndef SWITCH_HPP
#define SWITCH_HPP

#include <wx/wx.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <wx/stattext.h>
#include <wx/button.h>
#include <wx/notebook.h>
#include <wx/textctrl.h>
#include <wx/listctrl.h>
#include <wx/spinctrl.h>
#include <wx/sizer.h>
#include <wx/panel.h>

#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"


class App : public wxApp 
{
public:
    virtual bool OnInit();
};

wxIMPLEMENT_APP(App);


class NetworkSwitch
{
public:
    void startup();
    void shutdown();
    static void traffic(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* context);
private:
    std::array<pcpp::PcapLiveDevice*, 2> ports;
    const std::vector<std::string> ifnames{"sw-port0", "sw-port1"};
};


class DeviceWindow: public wxFrame 
{
public:
    DeviceWindow();
    void runDevice();
private:
    NetworkSwitch netSwitch;

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
