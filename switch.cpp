#include "switch.hpp"


void NetworkSwitch::startup()
{
    for (size_t i = 0; i < this->ports.size(); ++i) {
        this->ports[i] = (
            pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(ifnames[i])
        );
        if (this->ports[i] == NULL)
            throw std::runtime_error("Cannot find interfaces");

        if (!this->ports[i]->open())
            throw std::runtime_error("Cannot open device");
    }

    for (size_t i = 0; i < this->ports.size(); ++i) {
        this->ports[i]->startCapture(NetworkSwitch::traffic, this);
    }
}

void NetworkSwitch::shutdown()
{
     for (size_t i = 0; i < this->ports.size(); ++i) {
        if (this->ports[i] != NULL)
            this->ports[i]->stopCapture();
    }
}

void NetworkSwitch::traffic(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* context)
{
    // extract the stats object form the cookie
    // PacketStats* stats = (PacketStats*)cookie;
    // parsed the raw packet
    pcpp::Packet parsedPacket(packet);
    // collect stats from packet
    // stats->consumePacket(parsedPacket);
    // dev->sendPacket(**iter)
}


bool App::OnInit()
{
    DeviceWindow* frame = new DeviceWindow();
    frame->Show(true);
    frame->runDevice();
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
}

void DeviceWindow::runDevice()
{
    try {
        this->netSwitch.startup();
    } catch(const std::runtime_error& error) {
        std::cerr << error.what() << std::endl; // TODO: error dialog
    }
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

    auto cam = new wxListView(page);
    cam->AppendColumn(wxT("MAC adresa"));
    cam->AppendColumn(wxT("Port"));
    cam->AppendColumn(wxT("Časovač"));
    cam->SetColumnWidth(0, 250);
    cam->SetColumnWidth(1, 150);
    cam->SetColumnWidth(2, 150);

    auto heading = new wxBoxSizer(wxHORIZONTAL);
    heading->Add(title, 2, wxEXPAND | wxALL, 5);
    heading->Add(camClear, 0, wxEXPAND | wxALL, 5);

    auto camTimerRow = new wxBoxSizer(wxHORIZONTAL);
    camTimerRow->Add(timerLabel, 2, wxALL, 5);
    camTimerRow->Add(timerLimit, 2, wxALL, 5);
    camTimerRow->Add(timerConfirm, 1, wxALL, 5);

    auto layout = new wxBoxSizer(wxVERTICAL);
    layout->Add(heading, 0, wxEXPAND);
    layout->Add(camTimerRow);
    layout->Add(cam, 1, wxEXPAND);
    page->SetSizer(layout);

    camClear->Bind(wxEVT_BUTTON, &DeviceWindow::clearMACTable, this);
    timerConfirm->Bind(wxEVT_BUTTON, &DeviceWindow::setMACTimeout, this);
}

void DeviceWindow::statisticsPage(wxPanel* page)
{
    auto title = new wxStaticText(page, wxID_ANY, wxT("Štatistiky premávky"));
    auto font = title->GetFont();
    font.SetPointSize(14);
    title->SetFont(font);
    auto statsReset = new wxButton(page, wxID_ANY, wxT("Vynulovať"));

    auto statistics = new wxListView(page);
    statistics->AppendColumn("Protokol");
    statistics->AppendColumn("IN");
    statistics->AppendColumn("OUT");
    statistics->SetColumnWidth(0, 250);
    statistics->SetColumnWidth(1, 150);
    statistics->SetColumnWidth(2, 150);

    const std::vector<wxString> protocols{
        "Ethernet II", "ARP", "IP", "TCP", "UDP", "ICMP", "HTTP"
    };
    for (size_t i = 0; i < protocols.size(); ++i) {
        statistics->InsertItem(i, protocols[i]);
        statistics->SetItem(i, 1, "0");
        statistics->SetItem(i, 2, "0");
    }

    auto heading = new wxBoxSizer(wxHORIZONTAL);
    heading->Add(title, 3, wxEXPAND | wxALL, 5);
    heading->Add(statsReset, 1, wxEXPAND | wxALL, 5);

    auto layout = new wxBoxSizer(wxVERTICAL);
    layout->Add(heading, 0, wxEXPAND);
    layout->Add(statistics, 1, wxEXPAND);
    page->SetSizer(layout);

    statsReset->Bind(wxEVT_BUTTON, &DeviceWindow::resetTrafficStats, this);
}

void DeviceWindow::filtersPage(wxPanel* page)
{
    auto filterAddrLabel = new wxStaticText(page, wxID_ANY, wxT("MAC / IP adresa:"));
    auto filterDirLabel = new wxStaticText(page, wxID_ANY, wxT("Smer:"));
    auto filterProtoLabel = new wxStaticText(page, wxID_ANY, wxT("Protokol:"));

    auto filterAddr = new wxTextCtrl(page, wxID_ANY);
    wxString directions[] = {"IN", "OUT"};
    auto filterDir = new wxChoice(
        page, wxID_ANY, wxDefaultPosition, wxDefaultSize, 2, directions
    );
    wxString protocols[] = {
        "Ethernet II", "ARP", "IP", "TCP", "UDP", "ICMP", "HTTP"
    };
    auto filterProto = new wxChoice(
        page, wxID_ANY, wxDefaultPosition, wxDefaultSize, 7, protocols
    );
    auto filterAddRule = new wxButton(page, wxID_ANY, wxT("Pridať pravidlo"));

    auto filterRules = new wxListView(page);
    filterRules->AppendColumn("IP / MAC adresa");
    filterRules->AppendColumn("Smer");
    filterRules->AppendColumn("Protokol");
    filterRules->SetColumnWidth(0, 250);
    filterRules->SetColumnWidth(1, 100);
    filterRules->SetColumnWidth(2, 150);

    auto filterClearOne = new wxButton(page, wxID_ANY, wxT("Zmazať zvolené"));
    auto filterClearAll = new wxButton(page, wxID_ANY, wxT("Zmazať všetky"));

    auto filterNewRule = new wxFlexGridSizer(4, 2, 10, 10);
    filterNewRule->Add(filterAddrLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(filterAddr, 2, wxEXPAND);
    filterNewRule->Add(filterDirLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(filterDir, 2, wxEXPAND);
    filterNewRule->Add(filterProtoLabel, 1, wxALIGN_CENTER_VERTICAL);
    filterNewRule->Add(filterProto, 2, wxEXPAND);
    filterNewRule->Add(filterAddRule, 1, wxEXPAND);

    auto filterClear = new wxBoxSizer(wxHORIZONTAL);
    filterClear->Add(filterClearOne);
    filterClear->Add(filterClearAll);

    auto layout = new wxBoxSizer(wxVERTICAL);
    layout->Add(filterNewRule, 0, wxALL, 5);
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


void DeviceWindow::clearMACTable(wxCommandEvent& event)
{
    std::cout << "Tlačidlo" << std::endl;
    //Close(true);
}

void DeviceWindow::setMACTimeout(wxCommandEvent& event)
{

}

void DeviceWindow::resetTrafficStats(wxCommandEvent& event)
{

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
