#ifndef SWITCH_HPP
#define SWITCH_HPP

#include <wx/wx.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <vector>
#include <set>
#include <mutex>

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
    size_t age;
};

struct Interface {
    pcpp::PcapLiveDevice* dev;
    size_t port;
    bool up;
    unsigned short age;
};

enum ACLProtocol {
    ACL_NONE = 0, ACL_TCP, ACL_UDP, ACL_ICMP_REQUEST, ACL_ICMP_REPLY
};

// Ako bude ANY? (bit struct)
struct ACLRule {
    bool allow;
    struct {
        bool srcMAC;
        bool dstMAC;
        bool srcIP;
        bool dstIP;
        bool srcPort;
        bool dstPort;
    } any;  
    std::string srcMAC;
    std::string dstMAC;
    std::string srcIP;
    std::string dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    ACLProtocol protocol;
};

struct FilterForm {
    wxChoice* iface;
    wxChoice* dir;
    wxChoice* policy;
    wxTextCtrl* srcMac;
    wxTextCtrl* dstMac;
    wxTextCtrl* srcIp;
    wxTextCtrl* dstIp;
    wxTextCtrl* srcPort;
    wxTextCtrl* dstPort;
    wxChoice* proto;
};

class NetworkSwitch
{
public:
    void startup();
    void shutdown();
    void timer();
    void route(pcpp::Packet* packet, pcpp::PcapLiveDevice* srcPort);
    static void dispatch(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* port, void* context);
    void clearStats();
    void clearMACTable();

    std::unordered_map<std::string, CAMRecord> getMACTable();
    std::vector<std::string> getInterfaceNames() { return ifnames; }

    std::array<std::vector<ACLRule>, SWITCH_PORTS> inAcl;
    std::array<std::vector<ACLRule>, SWITCH_PORTS> outAcl;

    TrafficStats inboundStats;
    TrafficStats outboundStats;
    const std::vector<std::string> ifnames{"port1", "port2"};
    unsigned int macTimeout = 60;

private:
    bool checkACL(std::vector<ACLRule>& rules);
    void aggregateStats(TrafficStats& statsDir, pcpp::Packet* packet, size_t port);
    bool isPacketLooping(pcpp::RawPacket* packet);

    std::mutex macTableMutex;
    std::array<Interface, SWITCH_PORTS> ports;
    std::unordered_map<std::string, CAMRecord> macTable;

    // Opravy pre cyklenie rámcov a sledovanie odpojenia linky
    std::set<std::vector<uint8_t>> duplicates;
    const std::set<std::string> macAliveTraffic {
        "c2:04:b2:ed:00:00", "c2:05:b3:0e:00:00"
    };
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

    void refreshTrafficStats();
    void refreshCAMTable();
    void setTimeoutLabel();

    void clearMACTable(wxCommandEvent& event);
    void setMACTimeout(wxCommandEvent& event); 

    void timerTick(wxTimerEvent& event);
    void updateTrafficStats(wxCommandEvent& event);
    void resetTrafficStats(wxCommandEvent& event);
    void resetTimeout(wxFocusEvent& event);
    
    void addTrafficFilter(wxCommandEvent& event);
    void deleteTrafficFilter(wxCommandEvent& event);
    void deleteAllTrafficFilters(wxCommandEvent& event);

    void filterChooseACL();
    void filterChooseACL(wxCommandEvent& event);
    void appendRuleACL(ACLRule& rule);

    void filterChooseProtocol();
    void filterChooseProtocol(wxCommandEvent& event);

    void manageSyslogService(wxCommandEvent& event);
    void clearSyslogConsole(wxCommandEvent& event);

    std::vector<wxString> displayInterfaces();

    NetworkSwitch netSwitch;
    wxChoice* portStats;
    wxListView* stats;

    wxListView* cam;
    wxSpinCtrl* timerLimit;
    wxStaticText* recordTimeout;

    FilterForm aclNewRule;
    wxListView *filterRules;

    // Konštanty pre filtre
    const wxString directionsAcl[2] = {"IN", "OUT"};
    const wxString policiesAcl[2] = {"ALLOW", "DENY"};
    const wxString protoTypesAcl[5] = {
        "-", "TCP", "UDP", "ICMP Echo Reply (0)", "ICMP Echo Request (8)"
    };
};

#endif
