#include "switch.hpp"


void NetworkSwitch::startup()
{
    for (size_t i = 0; i < this->ports.size(); ++i) {
        this->ports[i] = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(ifnames[i]);

        if (this->ports[i] == NULL)
            throw std::runtime_error("Cannot find interface");

        if (!this->ports[i]->open())
            throw std::runtime_error("Cannot open interface");
    }

    for (size_t i = 0; i < this->ports.size(); ++i) {
        this->ports[i]->startCapture(NetworkSwitch::dispatch, this);
    }
}

void NetworkSwitch::shutdown()
{
    for (size_t i = 0; i < this->ports.size(); ++i) {
        this->ports[i]->stopCapture();
        this->ports[i]->close();
    }
}

void NetworkSwitch::dispatch(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* context)
{
    auto netSwitch = (NetworkSwitch*)context;
    if (!netSwitch->isPacketLooping(packet)) {
	    pcpp::Packet parsedPacket(packet);
        netSwitch->route(&parsedPacket, dev);
    }
}


void NetworkSwitch::route(pcpp::Packet* packet, pcpp::PcapLiveDevice* srcPort)
{
    pcpp::EthLayer* ethLayer = packet->getLayerOfType<pcpp::EthLayer>();
    if (ethLayer != NULL) {
        std::cout << std::endl
            << "Source MAC address: " << ethLayer->getSourceMac() << std::endl
            << "Destination MAC address: " << ethLayer->getDestMac() << std::endl
            << "Ether type = 0x" << std::hex << pcpp::netToHost16(ethLayer->getEthHeader()->etherType);
    }


    for (size_t i = 0; i < this->ports.size(); ++i) {
        if (srcPort != this->ports[i]) {
            this->aggregateStats(this->outboundStats, packet, i);
            this->ports[i]->sendPacket(packet);
        } else {
            if (ethLayer != NULL) {
                std::string mac = ethLayer->getSourceMac().toString();
                CAMRecord peer = {.port = i, .timer = 60};   // TODO: property change timer
                this->macTable[mac] = peer;
            }
            this->aggregateStats(this->inboundStats, packet, i);
        }
    }
}

bool NetworkSwitch::isPacketLooping(pcpp::RawPacket* packet)
{
    auto data = packet->getRawData();
	std::vector<uint8_t> serialized(data, data + packet->getRawDataLen());

	if (this->duplicates.count(serialized)) {
		this->duplicates.erase(serialized);
		return true;
	} else {
        this->duplicates.insert(serialized);
        return false;
    }
}

void NetworkSwitch::clearStats()
{
    for (size_t p = 0; p < this->ifnames.size(); ++p) {
        for (size_t t = 0; t < this->inboundStats[p].size(); ++t)
            this->inboundStats[p][t] = 0;
        for (size_t t = 0; t < this->outboundStats[p].size(); ++t)
            this->outboundStats[p][t] = 0;
    }
}

void NetworkSwitch::aggregateStats(TrafficStats& statsDir, pcpp::Packet* packet, size_t port)
{
    if (packet->isPacketOfType(pcpp::Ethernet))
        statsDir[port][PDU::EthII]++;
    if (packet->isPacketOfType(pcpp::IPv4) || 
               packet->isPacketOfType(pcpp::IPv6))
        statsDir[port][PDU::IP]++;
    if (packet->isPacketOfType(pcpp::ARP))
        statsDir[port][PDU::ARP]++;
    if (packet->isPacketOfType(pcpp::TCP))
        statsDir[port][PDU::TCP]++;
    if (packet->isPacketOfType(pcpp::UDP))
        statsDir[port][PDU::UDP]++;
    if (packet->isPacketOfType(pcpp::ICMP))
        statsDir[port][PDU::ICMP]++;
    if (packet->isPacketOfType(pcpp::HTTP))
        statsDir[port][PDU::HTTP]++;
}



bool App::OnInit()
{
    DeviceWindow* frame = new DeviceWindow();
    frame->Show(true);
    frame->runDevice();
    frame->Bind(wxEVT_CLOSE_WINDOW, &DeviceWindow::onClose, frame);
    return true;
}


DeviceWindow::DeviceWindow() : wxFrame(NULL, wxID_ANY, wxT("Softvérový prepínač"))
{
    auto menu = new wxNotebook(this, wxID_ANY);

    auto cam = new wxPanel(menu);
    this->camTablePage(cam);
    auto stats = new wxPanel(menu);
    this->statisticsPage(stats);
    auto filter = new wxPanel(menu);
    this->filtersPage(filter);
    auto syslog = new wxPanel(menu);
    this->syslogPage(syslog);

    menu->AddPage(cam, wxT("CAM tabuľka"));
    menu->AddPage(stats, wxT("Štatistiky"));
    menu->AddPage(filter, wxT("Filtre"));
    menu->AddPage(syslog, wxT("Syslog"));

    auto sizer = new wxBoxSizer(wxHORIZONTAL);
    sizer->SetMinSize(600, 400);
    sizer->Add(menu, 1, wxEXPAND | wxALL, 5);
    this->SetSizerAndFit(sizer);

    auto timer = new wxTimer();
    timer->Bind(wxEVT_TIMER, &DeviceWindow::updateTrafficStats, this);
    timer->Start(1000);
}

void DeviceWindow::runDevice()
{
    try {
        this->netSwitch.startup();
    } catch(const std::runtime_error& error) { 
        auto dialog = new wxMessageDialog(
            NULL, wxT("Sieťové rozhranie nebolo nájdené alebo sa nedá otvoriť!"),
            wxT("Chyba sieťových rozhraní"), wxOK | wxICON_ERROR
        );
        dialog->ShowModal();
        this->Close(true);
    }
}

void DeviceWindow::onClose(wxCloseEvent& event)
{
    this->netSwitch.shutdown();
    this->Destroy();
}


void DeviceWindow::camTablePage(wxPanel* page)
{
    auto title = new wxStaticText(page, wxID_ANY, wxT("Prepínacia tabuľka"));
    auto font = title->GetFont();
    font.SetPointSize(14);
    title->SetFont(font);
    auto camClear = new wxButton(page, wxID_ANY, wxT("Vymazať"));

    auto timerLabel = new wxStaticText(page, wxID_ANY, wxT("Časovač (s): "));
    auto timerLimit = new wxSpinCtrl(page, wxID_ANY);
    timerLimit->SetRange(0, 900);
    timerLimit->SetValue(60);
    auto timerConfirm = new wxButton(page, wxID_ANY, wxT("OK"));

    this->cam = new wxListView(page);
    this->cam->AppendColumn(wxT("MAC adresa"));
    this->cam->AppendColumn(wxT("Port"));
    this->cam->AppendColumn(wxT("Časovač"));
    this->cam->SetColumnWidth(0, 250);
    this->cam->SetColumnWidth(1, 150);
    this->cam->SetColumnWidth(2, 150);

    auto heading = new wxBoxSizer(wxHORIZONTAL);
    heading->Add(title, 2, wxEXPAND | wxALL, 5);
    heading->Add(camClear, 0, wxEXPAND | wxALL, 5);

    auto camTimerRow = new wxBoxSizer(wxHORIZONTAL);
    camTimerRow->Add(timerLabel, 2, wxALIGN_CENTER_VERTICAL | wxALL, 5);
    camTimerRow->Add(timerLimit, 2, wxALIGN_CENTER_VERTICAL | wxALL, 5);
    camTimerRow->Add(timerConfirm, 1, wxALIGN_CENTER_VERTICAL | wxALL, 5);

    auto layout = new wxBoxSizer(wxVERTICAL);
    layout->Add(heading, 0, wxEXPAND);
    layout->Add(camTimerRow);
    layout->Add(this->cam, 1, wxEXPAND);
    page->SetSizer(layout);

    camClear->Bind(wxEVT_BUTTON, &DeviceWindow::clearMACTable, this);
    timerConfirm->Bind(wxEVT_BUTTON, &DeviceWindow::setMACTimeout, this);
}

std::vector<wxString> DeviceWindow::displayInterfaces()
{
    auto ifn = this->netSwitch.getInterfaceNames();
    std::vector<wxString> ifnames(ifn.size());

    for (size_t i = 0; i < ifnames.size(); ++i)
        ifnames[i] = wxString(ifn[i]);

    return ifnames;
}

void DeviceWindow::statisticsPage(wxPanel* page)
{
    auto title = new wxStaticText(page, wxID_ANY, wxT("Štatistiky premávky"));
    auto font = title->GetFont();
    font.SetPointSize(14);
    title->SetFont(font);
    auto statsReset = new wxButton(page, wxID_ANY, wxT("Vynulovať"));

    auto portLabel = new wxStaticText(page, wxID_ANY, wxT("Rozhranie:"));
    auto ifnames = this->displayInterfaces();

    this->portStats = new wxChoice(
        page, wxID_ANY, wxDefaultPosition, wxDefaultSize, 
        (int)ifnames.size(), &ifnames[0]
    );
    this->portStats->SetSelection(0);

    this->stats = new wxListView(page);
    this->stats->AppendColumn("Protokol");
    this->stats->AppendColumn("IN");
    this->stats->AppendColumn("OUT");
    this->stats->SetColumnWidth(0, 250);
    this->stats->SetColumnWidth(1, 150);
    this->stats->SetColumnWidth(2, 150);

    auto heading = new wxBoxSizer(wxHORIZONTAL);
    heading->Add(title, 3, wxEXPAND | wxALL, 5);
    heading->Add(statsReset, 1, wxEXPAND | wxALL, 5);

    auto portSelection = new wxBoxSizer(wxHORIZONTAL);
    portSelection->Add(portLabel, 1, wxALIGN_CENTER_VERTICAL | wxALL, 5);
    portSelection->Add(this->portStats, 1, wxALIGN_CENTER_VERTICAL | wxALL, 5);

    auto layout = new wxBoxSizer(wxVERTICAL);
    layout->Add(heading, 0, wxEXPAND);
    layout->Add(portSelection);
    layout->Add(this->stats, 1, wxEXPAND);
    page->SetSizer(layout);

    statsReset->Bind(wxEVT_BUTTON, &DeviceWindow::resetTrafficStats, this);
    portStats->Bind(wxEVT_CHOICE, &DeviceWindow::updateTrafficStats, this);
}

void DeviceWindow::filtersPage(wxPanel* page)
{
    auto ifaceLabel = new wxStaticText(page, wxID_ANY, wxT("Rozhranie:"));
    auto dirLabel = new wxStaticText(page, wxID_ANY, wxT("Smer:"));

    auto newRuleLabel = new wxStaticText(page, wxID_ANY, wxT("Nové ACL pravidlo:"));
    auto font = newRuleLabel->GetFont();
    font.SetPointSize(13);
    newRuleLabel->SetFont(font);

    auto macSrcLabel = new wxStaticText(page, wxID_ANY, wxT("Zdrojová MAC adresa:"));
    auto macDstLabel = new wxStaticText(page, wxID_ANY, wxT("Cieľová MAC adresa:"));
    auto ipSrcLabel = new wxStaticText(page, wxID_ANY, wxT("Zdrojová IP adresa:"));
    auto ipDstLabel = new wxStaticText(page, wxID_ANY, wxT("Cieľová IP adresa:"));
    auto portSrcLabel = new wxStaticText(page, wxID_ANY, wxT("Zdrojový TCP/UDP port:"));
    auto portDstLabel = new wxStaticText(page, wxID_ANY, wxT("Cieľový TCP/UDP port:"));
    auto icmpMsgLabel = new wxStaticText(page, wxID_ANY, wxT("ICMP typ správy:"));

    auto ifaces = this->displayInterfaces();
    wxString directions[] = {"IN", "OUT"};
    wxString icmpMessages[] = {"Request", "Reply"};

    auto filterIface = new wxChoice(page, wxID_ANY, wxDefaultPosition, wxDefaultSize, 2, &ifaces[0]);
    auto filterDir = new wxChoice(page, wxID_ANY, wxDefaultPosition, wxDefaultSize, 2, directions);
    auto filterMacSrc = new wxTextCtrl(page, wxID_ANY);
    auto filterMacDst = new wxTextCtrl(page, wxID_ANY);
    auto filterIpSrc = new wxTextCtrl(page, wxID_ANY);
    auto filterIpDst = new wxTextCtrl(page, wxID_ANY);
    auto filterPortSrc = new wxTextCtrl(page, wxID_ANY);
    auto filterPortDst = new wxTextCtrl(page, wxID_ANY);
    auto icmpMsg = new wxChoice(page, wxID_ANY, wxDefaultPosition, wxDefaultSize, 2, icmpMessages);
    auto filterAddRule = new wxButton(page, wxID_ANY, wxT("Pridať pravidlo"));

    auto filterRules = new wxListView(page);
    filterRules->AppendColumn("MAC Src");
    filterRules->AppendColumn("MAC Dst");
    filterRules->AppendColumn("IP Src");
    filterRules->AppendColumn("IP Dst");
    filterRules->AppendColumn("Port Src");
    filterRules->AppendColumn("Port Dst");
    filterRules->AppendColumn("ICMP type");
    // filterRules->SetColumnWidth(0, 250);

    auto filterClearOne = new wxButton(page, wxID_ANY, wxT("Zmazať zvolené"));
    auto filterClearAll = new wxButton(page, wxID_ANY, wxT("Zmazať všetky"));

    auto filterNewRule = new wxFlexGridSizer(12, 2, 10, 10);
    filterNewRule->Add(ifaceLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(filterIface, 1, wxEXPAND);
    
    filterNewRule->Add(dirLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(filterDir, 1, wxEXPAND);

    filterNewRule->Add(newRuleLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->AddSpacer(1);

    filterNewRule->Add(macSrcLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(filterMacSrc, 1, wxEXPAND);

    filterNewRule->Add(macDstLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(filterMacDst, 1, wxEXPAND);
    
    filterNewRule->Add(ipSrcLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(filterIpSrc, 1, wxEXPAND);
    
    filterNewRule->Add(ipDstLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(filterIpDst, 1, wxEXPAND);
    
    filterNewRule->Add(portSrcLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(filterPortSrc, 1, wxEXPAND);
    
    filterNewRule->Add(portDstLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(filterPortDst, 1, wxEXPAND);

    filterNewRule->Add(icmpMsgLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(icmpMsg, 1, wxEXPAND);

    filterNewRule->AddSpacer(1);
    filterNewRule->Add(filterAddRule, 2, wxEXPAND);
    filterNewRule->AddGrowableCol(1, 0);

    auto filterClear = new wxBoxSizer(wxHORIZONTAL);
    filterClear->Add(filterClearOne);
    filterClear->Add(filterClearAll);

    auto layout = new wxBoxSizer(wxVERTICAL);
    layout->Add(filterNewRule, 0, wxEXPAND | wxALL, 5);
    layout->Add(filterRules, 1, wxEXPAND);
    layout->Add(filterClear, 0, wxEXPAND);
    page->SetSizer(layout);

    filterAddRule->Bind(wxEVT_BUTTON, &DeviceWindow::addTrafficFilter, this);
    filterClearOne->Bind(wxEVT_BUTTON, &DeviceWindow::deleteTrafficFilter, this);
    filterClearAll->Bind(wxEVT_BUTTON, &DeviceWindow::deleteAllTrafficFilters, this);
}

void DeviceWindow::syslogPage(wxPanel* page)
{
    auto sourceIPLabel = new wxStaticText(page, wxID_ANY, wxT("Zdrojová IP adresa:"));
    auto syslogIPLabel = new wxStaticText(page, wxID_ANY, wxT("Syslog IP adresa:"));
    auto sourceIP = new wxTextCtrl(page, wxID_ANY);
    auto syslogIP = new wxTextCtrl(page, wxID_ANY);
    auto syslogConnect = new wxButton(page, wxID_ANY, wxT("Spustiť"));

    auto syslogOutLabel = new wxStaticText(page, wxID_ANY, wxT("Odoslané správy:"));
    auto font = syslogOutLabel->GetFont();
    font.SetPointSize(12);
    syslogOutLabel->SetFont(font);
    auto syslogClear = new wxButton(page, wxID_ANY, wxT("Vymazať"));
    auto syslogMessages = new wxTextCtrl(
        page, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize,
        wxTE_MULTILINE | wxTE_READONLY
    );

    auto connection = new wxFlexGridSizer(3, 2, 10, 10);
    connection->Add(sourceIPLabel, 1, wxALIGN_CENTER_VERTICAL);
    connection->Add(sourceIP, 1, wxEXPAND);
    connection->Add(syslogIPLabel, 1, wxALIGN_CENTER_VERTICAL);
    connection->Add(syslogIP,1, wxEXPAND);
    connection->Add(syslogConnect);
    connection->AddGrowableCol(1, 0);

    auto syslogMsgHeading = new wxBoxSizer(wxHORIZONTAL);
    syslogMsgHeading->Add(syslogOutLabel, 2, wxEXPAND);
    syslogMsgHeading->Add(syslogClear, 0, wxEXPAND);

    auto layout = new wxBoxSizer(wxVERTICAL);
    layout->Add(connection, 0, wxEXPAND | wxALL, 5);
    layout->Add(syslogMsgHeading, 0, wxEXPAND | wxALL, 5);
    layout->Add(syslogMessages, 1, wxEXPAND | wxALL, 5);
    page->SetSizer(layout);

    syslogConnect->Bind(wxEVT_BUTTON, &DeviceWindow::manageSyslogService, this);
    syslogClear->Bind(wxEVT_BUTTON, &DeviceWindow::clearSyslogConsole, this);
}

void DeviceWindow::refreshTrafficStats()
{
    int port = this->portStats->GetSelection();
    size_t in, out;

    this->stats->DeleteAllItems();
    for (size_t i = 0; i < protocols.size(); ++i) {
        in = netSwitch.inboundStats[port][i];
        out = netSwitch.outboundStats[port][i];

        this->stats->InsertItem(i, protocols[i]);
        this->stats->SetItem(i, 1, wxString::Format(wxT("%ld"), in));
        this->stats->SetItem(i, 2, wxString::Format(wxT("%ld"), out));
    }
}

void DeviceWindow::refreshCAMTable()
{
    this->cam->DeleteAllItems();
    int i = 0;
    for (auto& it: this->netSwitch.macTable) {
        CAMRecord peer = it.second;
        this->cam->InsertItem(i, it.first);
        this->cam->SetItem(i, 1,  this->netSwitch.ifnames[peer.port]);
        this->cam->SetItem(i, 2,  wxString::Format(wxT("%ld"), peer.timer));
        i++;
    }
}


void DeviceWindow::clearMACTable(wxCommandEvent& event)
{
    this->netSwitch.macTable.clear();
    this->refreshCAMTable();
    //Close(true);
}

void DeviceWindow::setMACTimeout(wxCommandEvent& event)
{

}

void DeviceWindow::updateTrafficStats(wxEvent& event)
{
    this->refreshTrafficStats();
    this->refreshCAMTable();
}

void DeviceWindow::resetTrafficStats(wxCommandEvent& event)
{
    netSwitch.clearStats();
    this->updateTrafficStats(event);
}

void DeviceWindow::addTrafficFilter(wxCommandEvent& event)
{

}

void DeviceWindow::deleteAllTrafficFilters(wxCommandEvent& event)
{

}

void DeviceWindow::deleteTrafficFilter(wxCommandEvent& event)
{

}

void DeviceWindow::manageSyslogService(wxCommandEvent& event)
{

}

void DeviceWindow::clearSyslogConsole(wxCommandEvent& event)
{

}
