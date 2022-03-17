#include "switch.hpp"


#define PORT_ALIVE_SEC      5

void NetworkSwitch::startup()
{
    for (size_t i = 0; i < this->ports.size(); ++i) {
        this->ports[i].dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(ifnames[i]);

        if (this->ports[i].dev == NULL)
            throw std::runtime_error("Cannot find interface");

        if (!this->ports[i].dev->open())
            throw std::runtime_error("Cannot open interface");
    }

    for (size_t i = 0; i < this->ports.size(); ++i) {
        this->ports[i].dev->startCapture(NetworkSwitch::dispatch, this);
        this->ports[i].age = 0;
        this->ports[i].up = true;
    }
}

void NetworkSwitch::shutdown()
{
    for (size_t i = 0; i < this->ports.size(); ++i) {
        this->ports[i].dev->stopCapture();
        this->ports[i].dev->close();
    }
}

void NetworkSwitch::timer()
{
    macTableMutex.lock();
    for (size_t i = 0; i < this->ports.size(); ++i)
        this->ports[i].age++;

    for (auto record = this->macTable.begin(); record != this->macTable.end();) {
        record->second.age++;
        if (this->ports[record->second.port].age > PORT_ALIVE_SEC) {
            this->ports[record->second.port].up = false;
            record = this->macTable.erase(record);
        } else if (record->second.age > this->macTimeout) {
            record = this->macTable.erase(record);
        } else {
            record++;
        }
    }
    macTableMutex.unlock();
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
    if (ethLayer == NULL)
        return;
    /*
    std::cout << std::endl
            << "Source MAC address: " << ethLayer->getSourceMac() << std::endl
            << "Destination MAC address: " << ethLayer->getDestMac() << std::endl
            << "Ether type = 0x" << std::hex << pcpp::netToHost16(ethLayer->getEthHeader()->etherType);
    */

    std::string srcMac = ethLayer->getSourceMac().toString();
    std::string dstMac = ethLayer->getDestMac().toString();

    macTableMutex.lock();
    auto record = macTable.find(dstMac);
    bool unicast = record != macTable.end();
    bool ignore = this->macAliveTraffic.find(dstMac) != this->macAliveTraffic.end();

    for (size_t i = 0; i < this->ports.size(); ++i) {

        if (srcPort == this->ports[i].dev) {
            // FRAME INBOUND
            this->ports[i].age = 0;
            this->ports[i].up = true;
            if (ignore)
                continue;

            if (this->checkACL(this->inAcl[i])) {
                this->aggregateStats(this->inboundStats, packet, i);
                CAMRecord peer = {.port = i, .age = 0};
                this->macTable[srcMac] = peer;
            }

        } else {
            // FRAME OUTBOUND
            if (ignore) {
                this->ports[i].age = 0;
                this->ports[i].up = true;
                this->ports[i].dev->sendPacket(packet);
                continue;
            }

            if (!this->ports[i].up || (unicast && i != record->second.port)) {
                continue;
            }

            if (this->checkACL(this->outAcl[i])) {
                this->aggregateStats(this->outboundStats, packet, i);
                this->ports[i].dev->sendPacket(packet);
            }
        }
    }
    macTableMutex.unlock();
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

void NetworkSwitch::clearMACTable()
{
    macTableMutex.lock();
    this->macTable.clear();
    macTableMutex.unlock();
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

std::unordered_map<std::string, CAMRecord> NetworkSwitch::getMACTable()
{
    return this->macTable;
}

bool NetworkSwitch::checkACL(std::vector<ACLRule>& rules)
{
    for (auto& rule: rules) {
        //
    }
    return true;
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
    timer->Bind(wxEVT_TIMER, &DeviceWindow::timerTick, this);
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

    auto timerLabel = new wxStaticText(page, wxID_ANY, wxT("Časovač: "));
    this->recordTimeout = new wxStaticText(page, wxID_ANY, wxT(""));
    this->timerLimit = new wxSpinCtrl(page, wxID_ANY);
    this->timerLimit->SetRange(0, 900);
    this->setTimeoutLabel();
    this->timerLimit->SetValue(this->netSwitch.macTimeout);
    auto timerConfirm = new wxButton(page, wxID_ANY, wxT("Nastav"));

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
    camTimerRow->Add(timerLabel, 1, wxALIGN_CENTER_VERTICAL | wxALL, 5);
    camTimerRow->Add(recordTimeout, 2, wxALIGN_CENTER_VERTICAL | wxALL, 5);
    camTimerRow->Add(timerLimit, 1, wxEXPAND | wxALIGN_CENTER_VERTICAL | wxALL, 5);
    camTimerRow->Add(timerConfirm, 1, wxEXPAND | wxALIGN_CENTER_VERTICAL | wxALL, 5);

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
    
    auto policyLabel = new wxStaticText(page, wxID_ANY, wxT("Akcia:"));
    auto macSrcLabel = new wxStaticText(page, wxID_ANY, wxT("Zdrojová MAC adresa:"));
    auto macDstLabel = new wxStaticText(page, wxID_ANY, wxT("Cieľová MAC adresa:"));
    auto ipSrcLabel = new wxStaticText(page, wxID_ANY, wxT("Zdrojová IP adresa:"));
    auto ipDstLabel = new wxStaticText(page, wxID_ANY, wxT("Cieľová IP adresa:"));
    auto portSrcLabel = new wxStaticText(page, wxID_ANY, wxT("Zdrojový TCP/UDP port:"));
    auto portDstLabel = new wxStaticText(page, wxID_ANY, wxT("Cieľový TCP/UDP port:"));
    auto protoLabel = new wxStaticText(page, wxID_ANY, wxT("Protokol:"));

    auto ifaces = this->displayInterfaces();
    this->aclNewRule.iface = new wxChoice(page, wxID_ANY, wxDefaultPosition, wxDefaultSize, 2, &ifaces[0]);
    this->aclNewRule.dir = new wxChoice(page, wxID_ANY, wxDefaultPosition, wxDefaultSize, 2, this->directionsAcl);
    this->aclNewRule.policy = new wxChoice(page, wxID_ANY, wxDefaultPosition, wxDefaultSize, 2, this->policiesAcl);
    this->aclNewRule.srcMac = new wxTextCtrl(page, wxID_ANY);
    this->aclNewRule.dstMac = new wxTextCtrl(page, wxID_ANY);
    this->aclNewRule.srcIp = new wxTextCtrl(page, wxID_ANY);
    this->aclNewRule.dstIp = new wxTextCtrl(page, wxID_ANY);
    this->aclNewRule.srcPort = new wxTextCtrl(page, wxID_ANY);
    this->aclNewRule.dstPort = new wxTextCtrl(page, wxID_ANY);
    this->aclNewRule.proto = new wxChoice(page, wxID_ANY, wxDefaultPosition, wxDefaultSize, 5, this->protoTypesAcl);
    auto filterAddRule = new wxButton(page, wxID_ANY, wxT("Pridať pravidlo"));
    
    this->aclNewRule.proto->SetSelection(0);
    this->aclNewRule.iface->SetSelection(0);
    this->aclNewRule.dir->SetSelection(0);
    this->aclNewRule.policy->SetSelection(0);
    this->filterChooseProtocol();
    this->filterChooseACL();

    this->filterRules = new wxListView(page);
    this->filterRules->AppendColumn("Policy");
    this->filterRules->AppendColumn("MAC Src");
    this->filterRules->AppendColumn("MAC Dst");
    this->filterRules->AppendColumn("IP Src");
    this->filterRules->AppendColumn("IP Dst");
    this->filterRules->AppendColumn("Port Src");
    this->filterRules->AppendColumn("Port Dst");
    this->filterRules->AppendColumn("Protocol");
    // filterRules->SetColumnWidth(0, 250);

    auto filterClearOne = new wxButton(page, wxID_ANY, wxT("Zmazať zvolené"));
    auto filterClearAll = new wxButton(page, wxID_ANY, wxT("Zmazať všetky"));

    auto filterNewRule = new wxFlexGridSizer(13, 2, 10, 10);
    filterNewRule->Add(ifaceLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(this->aclNewRule.iface, 1, wxEXPAND);
    
    filterNewRule->Add(dirLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(this->aclNewRule.dir, 1, wxEXPAND);

    filterNewRule->Add(newRuleLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->AddSpacer(1);
    
    filterNewRule->Add(policyLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(this->aclNewRule.policy, 1, wxEXPAND);

    filterNewRule->Add(macSrcLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(this->aclNewRule.srcMac, 1, wxEXPAND);

    filterNewRule->Add(macDstLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(this->aclNewRule.dstMac, 1, wxEXPAND);
    
    filterNewRule->Add(ipSrcLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(this->aclNewRule.srcIp, 1, wxEXPAND);
    
    filterNewRule->Add(ipDstLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(this->aclNewRule.dstIp, 1, wxEXPAND);
    
    filterNewRule->Add(portSrcLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(this->aclNewRule.srcPort, 1, wxEXPAND);
    
    filterNewRule->Add(portDstLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(this->aclNewRule.dstPort, 1, wxEXPAND);

    filterNewRule->Add(protoLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(this->aclNewRule.proto, 1, wxEXPAND);

    filterNewRule->AddSpacer(1);
    filterNewRule->Add(filterAddRule, 2, wxEXPAND);
    filterNewRule->AddGrowableCol(1, 0);

    auto filterClear = new wxBoxSizer(wxHORIZONTAL);
    filterClear->Add(filterClearOne);
    filterClear->Add(filterClearAll);

    auto layout = new wxBoxSizer(wxVERTICAL);
    layout->Add(filterNewRule, 0, wxEXPAND | wxALL, 5);
    layout->Add(this->filterRules, 1, wxEXPAND);
    layout->Add(filterClear, 0, wxEXPAND);
    page->SetSizer(layout);


    this->aclNewRule.iface->Bind(wxEVT_CHOICE, &DeviceWindow::filterChooseACL, this);
    this->aclNewRule.dir->Bind(wxEVT_CHOICE, &DeviceWindow::filterChooseACL, this);
    this->aclNewRule.proto->Bind(wxEVT_CHOICE, &DeviceWindow::filterChooseProtocol, this);

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

void DeviceWindow::setTimeoutLabel()
{
    this->recordTimeout->SetLabel(
        wxString::Format(wxT("%i s"), this->netSwitch.macTimeout)
    );
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
    for (auto& it: this->netSwitch.getMACTable()) {
        CAMRecord peer = it.second;
        this->cam->InsertItem(i, it.first);
        this->cam->SetItem(i, 1,  this->netSwitch.ifnames[peer.port]);
        this->cam->SetItem(i, 2,  wxString::Format(wxT("%ld"), peer.age));
        i++;
    }
}


void DeviceWindow::timerTick(wxTimerEvent& event)
{
    this->netSwitch.timer();
    this->refreshTrafficStats();
    this->refreshCAMTable();
}

void DeviceWindow::clearMACTable(wxCommandEvent& event)
{
    this->netSwitch.clearMACTable();
    this->refreshCAMTable();
}

void DeviceWindow::setMACTimeout(wxCommandEvent& event)
{
    this->netSwitch.macTimeout = this->timerLimit->GetValue();
    this->setTimeoutLabel();
    auto dialog = new wxMessageDialog(
        NULL, wxT("Časovač na vypršanie záznamu MAC adries bol zmenený"),
        wxT("Časovač zmenený"), wxOK | wxICON_INFORMATION
    );
    dialog->ShowModal();
}

void DeviceWindow::updateTrafficStats(wxCommandEvent& event)
{
    this->refreshTrafficStats();
}

void DeviceWindow::resetTrafficStats(wxCommandEvent& event)
{
    netSwitch.clearStats();
    this->refreshTrafficStats();
}

void DeviceWindow::appendRuleACL(ACLRule& rule)
{
    auto i = this->filterRules->GetItemCount();
    bool portOn = (rule.protocol == ACLProtocol::ACL_TCP || rule.protocol == ACLProtocol::ACL_UDP);

    this->filterRules->InsertItem(i, (rule.allow) ? "allow": "deny");
    this->filterRules->SetItem(i, 1, (rule.any.srcMAC) ? "any": rule.srcMAC);
    this->filterRules->SetItem(i, 2, (rule.any.dstMAC) ? "any": rule.dstMAC);
    this->filterRules->SetItem(i, 3, (rule.any.srcIP) ? "any": rule.srcIP);
    this->filterRules->SetItem(i, 4, (rule.any.dstIP) ? "any": rule.dstIP);
    this->filterRules->SetItem(i, 5, 
        (portOn) ? ((rule.any.srcPort) ? "any": wxString::Format(wxT("%u"), rule.srcPort)): "-"
    );
    this->filterRules->SetItem(i, 6, 
        (portOn) ? ((rule.any.dstPort) ? "any": wxString::Format(wxT("%u"), rule.dstPort)): "-"
    );
    this->filterRules->SetItem(i, 7, this->protoTypesAcl[rule.protocol]);
}

void DeviceWindow::filterChooseACL()
{
    auto interface = this->aclNewRule.iface->GetSelection();
    auto direction = this->aclNewRule.dir->GetString(
        this->aclNewRule.dir->GetSelection()
    );

    if (direction == "IN") {
        for (auto& rule: this->netSwitch.inAcl[interface]) {
            this->appendRuleACL(rule);
        }
    } else if (direction == "OUT") {
        for (auto& rule: this->netSwitch.outAcl[interface]) {
            this->appendRuleACL(rule);
        }
    }
}

void DeviceWindow::filterChooseACL(wxCommandEvent& event)
{
    this->filterChooseACL();
}

void DeviceWindow::filterChooseProtocol()
{
    auto proto = static_cast<ACLProtocol>(this->aclNewRule.proto->GetSelection());
    bool on = false;
    if (proto == ACLProtocol::ACL_TCP || proto == ACLProtocol::ACL_UDP)
        on = true;

    this->aclNewRule.srcPort->Enable(on);
    this->aclNewRule.dstPort->Enable(on);
}

void DeviceWindow::filterChooseProtocol(wxCommandEvent& event)
{
    this->filterChooseProtocol();
}

void DeviceWindow::addTrafficFilter(wxCommandEvent& event)
{
    ACLRule rule;

    auto aclPolicy = this->aclNewRule.policy->GetString(
        this->aclNewRule.policy->GetSelection()
    );
    auto srcMacStr = this->aclNewRule.srcMac->GetValue().ToStdString();
    auto dstMacStr = this->aclNewRule.dstMac->GetValue().ToStdString();
    auto srcIpStr = this->aclNewRule.srcIp->GetValue().ToStdString();
    auto dstIpStr = this->aclNewRule.dstIp->GetValue().ToStdString();
    auto srcPortStr = this->aclNewRule.srcPort->GetValue();
    auto dstPortStr = this->aclNewRule.dstPort->GetValue();

    rule.allow = !(aclPolicy == "DENY");
    rule.protocol = static_cast<ACLProtocol>(this->aclNewRule.proto->GetSelection());

    pcpp::MacAddress srcMac(srcMacStr);
    if (srcMacStr == "") {
        rule.any.srcMAC = true;
    } else if (srcMac.isValid()) {
        rule.any.srcMAC = false;
        rule.srcMAC = srcMac.toString();
    } else {
        auto dialog = new wxMessageDialog(
            NULL, wxString::Format(wxT("Zdrojová MAC adresa '%s' je neplatná!"), srcMacStr),
            wxT("Chyba pravidla"), wxOK | wxICON_ERROR
        );
        dialog->ShowModal();
        return;
    }

    pcpp::MacAddress dstMac(dstMacStr);
    if (dstMacStr == "") {
        rule.any.dstMAC = true;
    } else if (dstMac.isValid()) {
        rule.any.dstMAC = false;
        rule.dstMAC = dstMac.toString();
    } else {
        auto dialog = new wxMessageDialog(
            NULL, wxString::Format(wxT("Cieľová MAC adresa '%s' je neplatná!"), dstMacStr),
            wxT("Chyba pravidla"), wxOK | wxICON_ERROR
        );
        dialog->ShowModal();
        return;
    }

    pcpp::IPv4Address srcIp(srcIpStr);
    if (srcIpStr == "") {
        rule.any.srcIP = true;
    } else if (srcIp.isValid()) {
        rule.any.srcIP = false;
        rule.srcIP = srcIp.toString();
    } else {
        auto dialog = new wxMessageDialog(
            NULL, wxString::Format(wxT("Zdrojová IP adresa '%s' je neplatná!"), srcIpStr),
            wxT("Chyba pravidla"), wxOK | wxICON_ERROR
        );
        dialog->ShowModal();
        return;
    }

    pcpp::IPv4Address dstIp(dstIpStr);
    if (dstIpStr == "") {
        rule.any.dstIP = true;
    } else if (dstIp.isValid()) {
        rule.any.dstIP = false;
        rule.dstIP = dstIp.toString();
    } else {
        auto dialog = new wxMessageDialog(
            NULL, wxString::Format(wxT("Cieľová IP adresa '%s' je neplatná!"), dstIpStr),
            wxT("Chyba pravidla"), wxOK | wxICON_ERROR
        );
        dialog->ShowModal();
        return;
    }

    long srcPort;
    bool validPort = srcPortStr.ToLong(&srcPort);
    if (srcPortStr == "") {
        rule.any.srcPort = true;
    } else if (validPort && (srcPort >= 0 && srcPort <= 65535)) {
        rule.any.srcPort = false;
        rule.srcPort = srcPort;
    } else {
        auto dialog = new wxMessageDialog(
            NULL, wxString::Format(wxT("Zdrojový port '%s' je neplatný!"), srcPortStr),
            wxT("Chyba pravidla"), wxOK | wxICON_ERROR
        );
        dialog->ShowModal();
        return;
    }

    long dstPort;
    validPort = dstPortStr.ToLong(&dstPort);
    if (dstPortStr == "") {
        rule.any.dstPort = true;
    } else if (validPort && (dstPort >= 0 && dstPort <= 65535)) {
        rule.any.dstPort = false;
        rule.dstPort = dstPort;
    } else {
        auto dialog = new wxMessageDialog(
            NULL, wxString::Format(wxT("Cieľový port '%s' je neplatný!"), srcPortStr),
            wxT("Chyba pravidla"), wxOK | wxICON_ERROR
        );
        dialog->ShowModal();
        return;
    }

    auto interface = this->aclNewRule.iface->GetSelection();
    auto direction = this->aclNewRule.dir->GetString(
        this->aclNewRule.dir->GetSelection()
    );

    if (direction == "IN") {
        this->netSwitch.inAcl[interface].push_back(rule);
    } else if (direction == "OUT") {
        this->netSwitch.outAcl[interface].push_back(rule);
    }
    this->appendRuleACL(rule);

    // clean form
}

void DeviceWindow::deleteAllTrafficFilters(wxCommandEvent& event)
{
    // Zisti, ktorý je acl je zvolený

    // vymaž zoznam vo swichi

    // preskresli pravidlá
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
