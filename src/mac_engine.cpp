#include <filesystem>
#include "mac_engine.h"
#include "port_finder.h"
#include "bpf_device.h"
#include "auditpipe.h"

namespace fs = std::filesystem;

bool MacEngine::matchesPacket(const PacketView &packet, const std::vector<std::string> &appNames)
{
    return std::any_of(appNames.begin(), appNames.end(), [&](const auto &str) {
        return PortFinder::ports({str}, packet.ipVersion()).contains(packet.sourcePort());
    });
}

void MacEngine::showConnections(const std::vector<std::string> &appNames)
{
    std::string(PortFinder::Connection::*fptr)() const = nullptr;
    fptr = _config.verbose ? &PortFinder::Connection::toVerboseString : &PortFinder::Connection::toString;

    auto showConnectionsForIPVersion = [&, this](IPVersion ipVersion)
    {
        std::cout << ipVersionToString(ipVersion) << "\n==\n";
        // Must run cmb as sudo to show all sockets, otherwise some are missed
        const auto connections4 = PortFinder::connections(appNames, ipVersion);
        for(const auto &conn : connections4)
            std::cout << (conn.*fptr)() << "\n";
    };

    if(_config.ipVersion == IPVersion::Both)
    {
        showConnectionsForIPVersion(IPv4);
        showConnectionsForIPVersion(IPv6);
    }
    else
        showConnectionsForIPVersion(_config.ipVersion);
}

void MacEngine::showTraffic(const std::vector<std::string> &appNames)
{
    auto bpfDevice = BpfDevice::create("en0");

    if(!bpfDevice)
        throw std::runtime_error("could not load bpf device");

    while(true)
    {
        bpfDevice->onPacketReceived([&, this](const PacketView &packet) {
            const std::string fullPath{PortFinder::portToPath(packet.sourcePort(), packet.ipVersion())};
            const std::string path = _config.verbose ? fullPath : static_cast<std::string>(fs::path(fullPath).filename());

            if(_config.ipVersion != IPVersion::Both)
                // Skip packets with wrong ipVersion
                if(packet.ipVersion() != _config.ipVersion)
                    return;

             if(packet.hasTransport())
             {
                if(appNames.empty())
                    displayPacket(packet, path);
                // If any app names are provided, only
                // display a packet if it matches one of those names
                else
                {
                    if(matchesPacket(packet, appNames))
                        displayPacket(packet, path);
                }
            }
        });
    }
}

void MacEngine::showExec(const std::vector<std::string> &appNames)
{
    AuditPipe auditPipe;

    auto onProcessStart = [](const auto &event)
    {
        std::cout << event.path << " started:" << std::endl;
    };

    auto onProcessEnd = [](auto&){};

    auditPipe.process(onProcessStart, onProcessEnd);
}


