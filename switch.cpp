#include "switch.hpp"


#define PORT_ALIVE_SEC      20
#define SYSLOG_PORT         514
#define FACILITY_LOCAL0     16


void NetworkSwitch::startup()
{
    for (size_t i = 0; i < this->ports.size(); ++i) {
        this->ports[i].dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(ifnames[i]);

        if (this->ports[i].dev == NULL)
            throw std::runtime_error("Cannot find interface");

        if (!this->ports[i].dev->open())
            throw std::runtime_error("Cannot open interface");
    }

    // all ports are listening for keepalive ping traffic and are down
    for (size_t i = 0; i < this->ports.size(); ++i) {
        this->ports[i].dev->startCapture(NetworkSwitch::dispatch, this);
        this->ports[i].age = 0;
        this->ports[i].up = false;
    }

    // SYSLOG defaults
    this->syslog.running = false;
    this->syslog.iface = 0;
    this->syslog.srcMAC = this->ports[syslog.iface].dev->getMacAddress().toString();
    this->syslog.dstMAC = "18:56:80:08:94:e5";  // wlan0
    this->syslog.srcIP = "";
    this->syslog.syslogIP = "";
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
    this->macTableMutex.lock();
    for (size_t i = 0; i < this->ports.size(); ++i)
        this->ports[i].age++;

    for (auto record = this->macTable.begin(); record != this->macTable.end();) {
        record->second.age++;

        if (this->ports[record->second.port].age >= PORT_ALIVE_SEC) {
            this->ports[record->second.port].up = false;
            record = this->macTable.erase(record);
        } else if (record->second.age > this->macTimeout) {
            record = this->macTable.erase(record);
        } else {
            record++;
        }
    }
    this->macTableMutex.unlock();

    /*
    std::ostringstream s;
    s << "Timeout of record with MAC address [" << record->first;
    s << "] on port " << this->ifnames[record->second.port];
    this->syslogSend(SyslogSeverity::INFORMATIONAL, s.str());
    */
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
    if (!packet->isPacketOfType(pcpp::Ethernet))
        return;

    pcpp::EthLayer* ethLayer = packet->getLayerOfType<pcpp::EthLayer>();
    const std::string srcMac = ethLayer->getSourceMac().toString();
    const std::string dstMac = ethLayer->getDestMac().toString();
    const bool ignore = (
        this->macAliveTraffic.count(srcMac) || this->macAliveTraffic.count(dstMac)
    );

    const auto cam = this->getMACTable();
    const auto record = cam.find(dstMac);
    const bool unicast = cam.count(dstMac);

    ACLRule frameACL;
    frameACLPreprocess(frameACL, packet);

    for (size_t i = 0; i < this->ports.size(); ++i) {
        if (srcPort == this->ports[i].dev) {
            // FRAME INBOUND
            this->macTableMutex.lock();
            this->ports[i].age = 0;
            this->ports[i].up = true;
            this->macTableMutex.unlock();
            if (ignore) {
                continue;
            }

            if (this->checkACL(frameACL, this->inAcl[i])) {
                this->aggregateStats(this->inboundStats, packet, i);
                CAMRecord peer = {.port = i, .age = 0};
                this->addMACRecord(srcMac, peer);
            }

        } else {
            // FRAME OUTBOUND
            if (ignore) {
                this->ports[i].dev->sendPacket(packet);
                continue;
            }
            this->macTableMutex.lock();
            bool up = this->ports[i].up;
            this->macTableMutex.unlock();

            if (!up || (unicast && i != record->second.port)) {
                continue;
            }

            if (this->checkACL(frameACL, this->outAcl[i])) {
                this->aggregateStats(this->outboundStats, packet, i);
                this->ports[i].dev->sendPacket(packet);
            }
        }
    }
}

bool NetworkSwitch::isPacketLooping(pcpp::RawPacket* packet)
{
    this->mutex_duplicates.lock();
    auto data = packet->getRawData();
	std::vector<uint8_t> serialized(data, data + packet->getRawDataLen());

	if (this->duplicates.count(serialized)) {
		this->duplicates.erase(serialized);
        this->mutex_duplicates.unlock();
		return true;
	}
    
    this->duplicates.insert(serialized);
    this->mutex_duplicates.unlock();
    return false;
}

void NetworkSwitch::clearMACTable()
{
    this->macTableMutex.lock();
    this->macTable.clear();
    this->macTableMutex.unlock();

    this->syslogSend(SyslogSeverity::NOTICE, "Reset of CAM table");
}

void NetworkSwitch::addMACRecord(std::string mac, CAMRecord& peer)
{
    this->macTableMutex.lock();
    bool exists = this->macTable.count(mac);

    if (exists && this->macTable[mac].port != peer.port) {
        auto port = this->macTable[mac].port;
        for (auto record = this->macTable.begin(); record != this->macTable.end();) {
            if (record->second.port == port) {
                record = this->macTable.erase(record);
            } else {
                record++;
            }
        }
    }
    this->macTable[mac] = peer;
    this->macTableMutex.unlock();

    if (!exists) {
        std::ostringstream s;
        s << "Device with MAC address [" << mac<< "] available on " << this->ifnames[peer.port];
        this->syslogSend(SyslogSeverity::INFORMATIONAL, s.str());
    }
}

void NetworkSwitch::clearStats()
{
    statsMutex.lock();
    for (size_t p = 0; p < this->ifnames.size(); ++p) {
        for (size_t t = 0; t < this->inboundStats[p].size(); ++t)
            this->inboundStats[p][t] = 0;
        for (size_t t = 0; t < this->outboundStats[p].size(); ++t)
            this->outboundStats[p][t] = 0;
    }
    statsMutex.unlock();
}

void NetworkSwitch::aggregateStats(TrafficStats& statsDir, pcpp::Packet* packet, size_t port)
{
    statsMutex.lock();
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
    statsMutex.unlock();
}

std::unordered_map<std::string, CAMRecord> NetworkSwitch::getMACTable()
{
    this->macTableMutex.lock();
    auto macTable = this->macTable;
    this->macTableMutex.unlock();
    return macTable;
}

void NetworkSwitch::setMACTimeout(size_t timeout)
{
    this->macTableMutex.lock();
    this->macTimeout = timeout;
    this->macTableMutex.unlock();

    std::ostringstream s;
    s << "Change of timeout for CAM records to " << timeout << " seconds";
    this->syslogSend(SyslogSeverity::NOTICE, s.str());
}

int NetworkSwitch::getMACTimeout()
{
    this->macTableMutex.lock();
    auto timeout = this->macTimeout;
    this->macTableMutex.unlock();
    return timeout;
}

void NetworkSwitch::getStats(size_t port, size_t proto, size_t& inbound, size_t& outbound)
{
    this->statsMutex.lock();
    inbound = this->inboundStats[port][proto];
    outbound = this->outboundStats[port][proto];
    this->statsMutex.unlock();
}

void NetworkSwitch::addACLRule(size_t interface, ACLDirection direction, ACLRule &rule)
{
    this->aclMutex.lock();
    if (direction == ACLDirection::ACL_DIR_IN) {
        this->inAcl[interface].push_back(rule);
    } else if (direction == ACLDirection::ACL_DIR_OUT) {
        this->outAcl[interface].push_back(rule);
    }
    this->aclMutex.unlock();

    std::ostringstream s;
    s << "New ACL rule on '" << this->ifnames[interface] << "' in direction  ";
    s << ((direction == ACLDirection::ACL_DIR_IN) ? "IN" : "OUT");
    this->syslogSend(SyslogSeverity::WARNING, s.str());
}

void NetworkSwitch::clearACLRules(size_t interface, ACLDirection direction)
{
    this->aclMutex.lock();
    if (direction == ACLDirection::ACL_DIR_IN) {
        this->inAcl[interface].clear();
    } else if (direction == ACLDirection::ACL_DIR_OUT) {
        this->outAcl[interface].clear();
    }
    this->aclMutex.unlock();

    std::ostringstream s;
    s << "Delete all ACL rules on '" << this->ifnames[interface] << "' in direction  ";
    s << ((direction == ACLDirection::ACL_DIR_IN) ? "IN" : "OUT");
    this->syslogSend(SyslogSeverity::WARNING, s.str());
}

void NetworkSwitch::removeACLRule(size_t interface, ACLDirection direction, size_t idx)
{
    this->aclMutex.lock();
    if (direction == ACLDirection::ACL_DIR_IN) {
        this->inAcl[interface].erase(this->inAcl[interface].begin() + idx);
    } else if (direction == ACLDirection::ACL_DIR_OUT) {
         this->outAcl[interface].erase(this->outAcl[interface].begin() + idx);
    }
    this->aclMutex.unlock();
}

std::vector<ACLRule> NetworkSwitch::getACLRules(size_t interface, ACLDirection direction)
{
    std::vector<ACLRule> rules;
    this->aclMutex.lock();
    if (direction == ACLDirection::ACL_DIR_IN) {
        rules = this->inAcl[interface];
    } else if (direction == ACLDirection::ACL_DIR_OUT) {
        rules = this->outAcl[interface];
    }
    this->aclMutex.unlock();
    return rules;
}

void NetworkSwitch::frameACLPreprocess(ACLRule& frame, pcpp::Packet* packet)
{
    frame.any.srcMAC = true;
    frame.any.dstMAC = true;
    frame.any.srcIP = true;
    frame.any.dstIP = true;
    frame.any.srcPort = true;
    frame.any.dstPort = true;
    frame.protocol = ACLProtocol::ACL_NONE;

    if (packet->isPacketOfType(pcpp::Ethernet)) {
        auto eth = packet->getLayerOfType<pcpp::EthLayer>();
        frame.srcMAC = eth->getSourceMac().toString();
        frame.dstMAC = eth->getDestMac().toString();
        frame.any.srcMAC = false;
        frame.any.dstMAC = false;
    }

    if (packet->isPacketOfType(pcpp::IPv4)) {
        auto eth = packet->getLayerOfType<pcpp::IPv4Layer>();
        frame.srcIP = eth->getSrcIPv4Address().toString();
        frame.dstIP = eth->getDstIPv4Address().toString();
        frame.any.srcIP = false;
        frame.any.dstIP = false;
    }

    if (packet->isPacketOfType(pcpp::TCP)) {
        auto eth = packet->getLayerOfType<pcpp::TcpLayer>();
        frame.srcPort = eth->getSrcPort();
        frame.dstPort = eth->getDstPort();
        frame.any.srcPort = false;
        frame.any.dstPort = false;
        frame.protocol = ACLProtocol::ACL_TCP;
    }

    if (packet->isPacketOfType(pcpp::UDP)) {
        auto eth = packet->getLayerOfType<pcpp::UdpLayer>();
        frame.srcPort = eth->getSrcPort();
        frame.dstPort = eth->getDstPort();
        frame.any.srcPort = false;
        frame.any.dstPort = false;
        frame.protocol = ACLProtocol::ACL_UDP;
    }

    if (packet->isPacketOfType(pcpp::ICMP)) {
        auto eth = packet->getLayerOfType<pcpp::IcmpLayer>();
        auto msg = eth->getMessageType();
        if (msg == pcpp::IcmpMessageType::ICMP_ECHO_REPLY)
            frame.protocol = ACLProtocol::ACL_ICMP_REPLY;
        else if (msg == pcpp::IcmpMessageType::ICMP_ECHO_REQUEST)
            frame.protocol = ACLProtocol::ACL_ICMP_REQUEST;
    }
}

bool NetworkSwitch::checkACL(ACLRule& frame, std::vector<ACLRule>& rules)
{
    this->aclMutex.lock();
    for (auto& rule: rules) {

        if (!(rule.any.srcMAC || (!rule.any.srcMAC && !frame.any.srcMAC && rule.srcMAC == frame.srcMAC)))
            continue;
        if (!(rule.any.dstMAC || (!rule.any.dstMAC && !frame.any.dstMAC && rule.dstMAC == frame.dstMAC)))
            continue;
        if (!(rule.any.srcIP || (!rule.any.srcIP && !frame.any.srcIP && rule.srcIP == frame.srcIP)))
            continue;
        if (!(rule.any.dstIP || (!rule.any.dstIP && !frame.any.dstIP && rule.dstIP == frame.dstIP)))
            continue;
        if (rule.protocol != frame.protocol)
            continue;
        if (rule.protocol == ACLProtocol::ACL_TCP || rule.protocol == ACLProtocol::ACL_UDP) {

            if (!(rule.any.srcPort || (!rule.any.srcPort && !frame.any.srcPort && rule.srcPort == frame.srcPort)))
                continue;
            if (!(rule.any.dstPort || (!rule.any.dstPort && !frame.any.dstPort && rule.dstPort == frame.dstPort)))
                continue;
        }

        this->aclMutex.unlock();
        return rule.allow;
    }
    this->aclMutex.unlock();
    return true;
}

void NetworkSwitch::syslogSend(SyslogSeverity severity, std::string message)
{
    if (!this->syslog.running)
        return;

    auto priority = FACILITY_LOCAL0 * 8 + severity;
    
    auto now = std::chrono::system_clock::now();
    auto tm = std::chrono::system_clock::to_time_t(now);

    std::ostringstream logger;
    logger << "<" << priority << ">1 ";
    logger << std::put_time(localtime(&tm), "%FT%TZ") << " ";
    logger <<  this->syslog.srcIP << "     " << "switch" << " ";
    logger << message;

    pcpp::EthLayer eth(
        pcpp::MacAddress(this->syslog.srcMAC),
        pcpp::MacAddress(this->syslog.dstMAC)
    );
    pcpp::IPv4Layer ip(
        pcpp::IPv4Address(this->syslog.srcIP),
        pcpp::IPv4Address(this->syslog.syslogIP)
    );
    ip.getIPv4Header()->timeToLive = 20;
    pcpp::UdpLayer udp(SYSLOG_PORT, SYSLOG_PORT);

    std::string x = logger.str();
    std::vector<uint8_t> data(x.begin(), x.end());
    pcpp::PayloadLayer payload(&data[0], data.size(), true);

    pcpp::Packet datagram(100);
    datagram.addLayer(&eth);
    datagram.addLayer(&ip);
    datagram.addLayer(&udp);
    datagram.addLayer(&payload);
    datagram.computeCalculateFields();

    // ? Treba štatistiky a ACL
    this->ports[this->syslog.iface].dev->sendPacket(&datagram);
}