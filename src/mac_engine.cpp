#include <filesystem>
#include "mac_engine.h"
#include "port_finder.h"
#include "bpf_device.h"

namespace fs = std::filesystem;

bool MacEngine::matchesPacket(const PacketView &packet, const std::vector<std::string> &appNames)
{
    return std::any_of(appNames.begin(), appNames.end(), [&](const auto &str) {
        return PortFinder::ports({str}, packet.ipVersion()).contains(packet.sourcePort());
    });
}

void MacEngine::showConnections(const std::vector<std::string> &appNames, IPVersion ipVersion)
{
    if(ipVersion == Both)
    {
        showConnections(appNames, IPv4);
        showConnections(appNames, IPv6);
        return;
    }
    std::string(PortFinder::Connection::*fptr)() const = nullptr;
    fptr = _config.verbose ? &PortFinder::Connection::toVerboseString : &PortFinder::Connection::toString;

    // Must run cmb as sudo to show all sockets, otherwise some are missed
    std::cout << "Connections for ";
    for(const auto &name : appNames)
        std::cout << name << " " << "\n";

    std::cout << ipVersionToString(ipVersion) << "\n==\n";
    const auto connections4 = PortFinder::connections(appNames, ipVersion);
    for(const auto &conn : connections4)
        std::cout << (conn.*fptr)() << "\n";
}

void MacEngine::showTraffic(const std::vector<std::string> &appNames, IPVersion ipVersion)
{
    auto bpfDevice = BpfDevice::create("en0");

    if(!bpfDevice)
        throw std::runtime_error("could not load bpf device");

    while(true)
    {
        bpfDevice->onPacketReceived([&, this](const PacketView &packet) {
            const std::string fullPath{PortFinder::portToPath(packet.sourcePort(), packet.ipVersion())};
            const std::string path = _config.verbose ? fullPath : static_cast<std::string>(fs::path(fullPath).filename());

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


