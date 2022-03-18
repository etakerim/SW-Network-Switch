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
#include <chrono>
#include <sstream>
#include <iomanip>

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
#include "UdpLayer.h"
#include "IcmpLayer.h"
#include "MacAddress.h"
#include "IpAddress.h"
#include "PayloadLayer.h"

#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"


class App : public wxApp 
{
public:
    virtual bool OnInit();
};


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

// Musí byť totožné s zoznamami reťazcov v DeviceWindow
enum ACLProtocol {
    ACL_NONE = 0,
    ACL_TCP,
    ACL_UDP,
    ACL_ICMP_REPLY,
    ACL_ICMP_REQUEST,
};

enum ACLDirection {
    ACL_DIR_IN = 0,
    ACL_DIR_OUT 
};

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

struct SyslogClient {
    bool running;
    size_t iface;
    std::string srcMAC;
    std::string dstMAC;
    std::string srcIP;
    std::string syslogIP;
};

enum SyslogSeverity {
    EMERGENCY = 0,
    ALERT,
    CRITICAL,
    ERROR,
    WARNING,
    NOTICE,
    INFORMATIONAL,
    DEBUG
};

class NetworkSwitch
{
public:
    void startup();
    void shutdown();
    void timer();
    void route(pcpp::Packet* packet, pcpp::PcapLiveDevice* srcPort);
    static void dispatch(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* port, void* context);
    std::vector<std::string> getInterfaceNames() { return ifnames; }

    int getMACTimeout();
    void setMACTimeout(size_t timeout);

    void clearMACTable();
    void addMACRecord(std::string mac, CAMRecord& peer);
    std::unordered_map<std::string, CAMRecord> getMACTable();

    void getStats(size_t port, size_t proto, size_t& inbound, size_t& outbound);
    void clearStats();

    void addACLRule(size_t interface, ACLDirection direction, ACLRule &rule);
    void clearACLRules(size_t interface, ACLDirection direction);
    void removeACLRule(size_t interface, ACLDirection direction, size_t idx);
    std::vector<ACLRule> getACLRules(size_t interface, ACLDirection direction);

    void syslogSend(SyslogSeverity severity, std::string message);

    const std::vector<std::string> ifnames{"port1", "port2"};
    SyslogClient syslog;

private:
    void frameACLPreprocess(ACLRule& frame, pcpp::Packet* packet);
    bool checkACL(ACLRule& frame, std::vector<ACLRule>& rules);
    void aggregateStats(TrafficStats& statsDir, pcpp::Packet* packet, size_t port);
    bool isPacketLooping(pcpp::RawPacket* packet);

    std::mutex macTableMutex;
    std::mutex statsMutex;
    std::mutex aclMutex;

    std::array<Interface, SWITCH_PORTS> ports;
    std::unordered_map<std::string, CAMRecord> macTable;
    size_t macTimeout = 60;

    TrafficStats inboundStats;
    TrafficStats outboundStats;

    std::array<std::vector<ACLRule>, SWITCH_PORTS> inAcl;
    std::array<std::vector<ACLRule>, SWITCH_PORTS> outAcl;

    // Fixes for frame cycling and ignore for keepalive ping traffic
    std::set<std::vector<uint8_t>> duplicates;
    const std::set<std::string> macAliveTraffic{
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
    // ----------------- GUI Layout ---------------------
    void camTablePage(wxPanel* page);
    void statisticsPage(wxPanel* page);
    void filtersPage(wxPanel* page);
    void syslogPage(wxPanel* page);

    // ----------------- MAC Table tab ---------------------
    void refreshCAMTable();
    void clearMACTable(wxCommandEvent& event);
    void setMACTimeout(wxCommandEvent& event);
    void setTimeoutLabel();

    // ----------------- Traffic stats tab ---------------------
    void updateTrafficStats();
    void updateTrafficStats(wxCommandEvent& event);
    void resetTrafficStats(wxCommandEvent& event);

    // ----------------- ACL rules tab ---------------------
    void appendRuleACL(ACLRule& rule);
    void filterChooseACL();
    void filterChooseACL(wxCommandEvent& event);
    void filterChooseProtocol();
    void filterChooseProtocol(wxCommandEvent& event);
    void clearACLForm();
    void addTrafficFilter(wxCommandEvent& event);
    void deleteAllTrafficFilters(wxCommandEvent& event);
    void deleteTrafficFilter(wxCommandEvent& event);

    // ----------------- Timer tick tab ---------------------
    void timerTick(wxTimerEvent& event);

    // ----------------- Syslog tab ---------------------
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
    wxListView* filterRules;

    wxTextCtrl* sourceIP;
    wxTextCtrl* syslogIP;
    wxButton* syslogConnect;
    wxTextCtrl* syslogMessages;

    // Konštanty pre filtre
    const wxString directionsAcl[2] = {"IN", "OUT"};
    const wxString policiesAcl[2] = {"ALLOW", "DENY"};
    const wxString protoTypesAcl[5] = {
        "-", "TCP", "UDP", "ICMP Echo Reply (0)", "ICMP Echo Request (8)"
    };
};

#endif