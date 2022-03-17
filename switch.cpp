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
    this->macTableMutex.lock();
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
    this->macTableMutex.unlock();
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

    std::string srcMac = ethLayer->getSourceMac().toString();
    std::string dstMac = ethLayer->getDestMac().toString();
    const bool ignore = this->macAliveTraffic.find(dstMac) != this->macAliveTraffic.end();

    auto cam = this->getMACTable();
    auto record = cam.find(dstMac);
    bool unicast = record != cam.end();

    for (size_t i = 0; i < this->ports.size(); ++i) {

        if (srcPort == this->ports[i].dev) {
            // FRAME INBOUND
            this->macTableMutex.lock();
            this->ports[i].age = 0;
            this->ports[i].up = true;
            this->macTableMutex.unlock();
            if (ignore)
                continue;

            if (this->checkACL(packet, this->inAcl[i])) {
                this->aggregateStats(this->inboundStats, packet, i);
                CAMRecord peer = {.port = i, .age = 0};
                this->addMACRecord(srcMac, peer);
            }

        } else {
            // FRAME OUTBOUND
            if (ignore) {
                this->macTableMutex.lock();
                this->ports[i].age = 0;
                this->ports[i].up = true;
                this->macTableMutex.unlock();
                this->ports[i].dev->sendPacket(packet);
                continue;
            }
            this->macTableMutex.lock();
            bool up = this->ports[i].up;
            this->macTableMutex.unlock();

            if (!up || (unicast && i != record->second.port)) {
                continue;
            }

            if (this->checkACL(packet, this->outAcl[i])) {
                this->aggregateStats(this->outboundStats, packet, i);
                this->ports[i].dev->sendPacket(packet);
            }
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

void NetworkSwitch::clearMACTable()
{
    this->macTableMutex.lock();
    this->macTable.clear();
    this->macTableMutex.unlock();
}

void NetworkSwitch::addMACRecord(std::string mac, CAMRecord& peer)
{
    this->macTableMutex.lock();
    this->macTable[mac] = peer;
    this->macTableMutex.unlock();
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
        rules =  this->outAcl[interface];
    }
    this->aclMutex.unlock();
    return rules;
}

bool NetworkSwitch::checkACL(pcpp::Packet* packet, std::vector<ACLRule>& rules)
{
    this->aclMutex.lock();
    for (auto& rule: rules) {
        
    }
    this->aclMutex.unlock();
    return true;
}