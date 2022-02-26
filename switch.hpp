#ifndef SWITCH_HPP
#define SWITCH_HPP

#include <wx/wx.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <vector>
#include <set>

#include <wx/stattext.h>
#include <wx/button.h>
#include <wx/notebook.h>
#include <wx/textctrl.h>
#include <wx/listctrl.h>
#include <wx/spinctrl.h>
#include <wx/sizer.h>
#include <wx/panel.h>

#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"

#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"


class App : public wxApp 
{
public:
    virtual bool OnInit();
};

wxIMPLEMENT_APP(App);

#define SWITCH_PORTS    2
enum PDU {EthII = 0, IP, ARP, TCP, UDP, ICMP, HTTP, count};
const std::array<wxString, PDU::count> protocols{
    "Ethernet II", "IP", "ARP", "TCP", "UDP", "ICMP", "HTTP"
};
typedef std::array<std::array<size_t, PDU::count>, SWITCH_PORTS> TrafficStats;

struct CAMRecord {
    size_t port;
    size_t timer;
};

class NetworkSwitch
{
public:
    void startup();
    void shutdown();
    void route(pcpp::Packet* packet, pcpp::PcapLiveDevice* srcPort);
    static void dispatch(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* port, void* context);

    void clearStats();
    std::vector<std::string> getInterfaceNames() { return ifnames; }

    TrafficStats inboundStats;
    TrafficStats outboundStats;
    const std::vector<std::string> ifnames{"port1", "port2"};
    std::unordered_map<std::string, CAMRecord> macTable;

private:
    void aggregateStats(TrafficStats& statsDir, pcpp::Packet* packet, size_t port);
    bool isPacketLooping(pcpp::RawPacket* packet);

    std::array<pcpp::PcapLiveDevice*, SWITCH_PORTS> ports;
    std::set<std::vector<uint8_t>> duplicates;
};


class DeviceWindow: public wxFrame 
{
public:
    DeviceWindow();
    void runDevice();
    void onClose(wxCloseEvent& event);

private:
    void camTablePage(wxPanel* page);
    void statisticsPage(wxPanel* page);
    void filtersPage(wxPanel* page);
    void syslogPage(wxPanel* page);

    void clearMACTable(wxCommandEvent& event);
    void setMACTimeout(wxCommandEvent& event); 

    void updateTrafficStats(wxEvent& event);
    void resetTrafficStats(wxCommandEvent& event);
    
    void addTrafficFilter(wxCommandEvent& event);
    void deleteTrafficFilter(wxCommandEvent& event);
    void deleteAllTrafficFilters(wxCommandEvent& event);

    void manageSyslogService(wxCommandEvent& event);
    void clearSyslogConsole(wxCommandEvent& event);

    NetworkSwitch netSwitch;
    wxChoice *portStats;
    wxListView *stats;
    wxListView *cam;
};

#endif
