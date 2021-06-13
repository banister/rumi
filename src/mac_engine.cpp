#include <filesystem>
#include "mac_engine.h"
#include "port_finder.h"
#include "bpf_device.h"
#include "auditpipe.h"

namespace fs = std::filesystem;

namespace
{
    std::string basename(const std::string& path)
    {
        return static_cast<std::string>(fs::path(path).filename());
    }
}

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
        const auto connections = PortFinder::connections(appNames, ipVersion);
        for(const auto &conn : connections)
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
    BpfDevice bpfDevice{"en0"};

    while(true)
    {
        bpfDevice.onPacketReceived([&, this](const PacketView &packet) {
            const std::string fullPath{PortFinder::portToPath(packet.sourcePort(), packet.ipVersion())};
            const std::string path = _config.verbose ? fullPath : basename(fullPath);

            if(_config.ipVersion != IPVersion::Both)
                // Skip packets with unwanted ipVersion
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

    // Execute this callback whenever a process starts up
    auditPipe.onProcessStarted([this](const auto &event)
    {
        // Show path of process executable
        std::cout << (_config.verbose ? event.path : basename(event.path)) << " ";

        for(size_t index=0; const auto &arg : event.arguments)
        {
            // Skip argv[0] (program name) as we already display the path
            if(index != 0)
                std::cout << arg << " ";

            ++index;
        }

        std::cout << std::endl;
    });

    // Infinite loop
    auditPipe.readLoop();
}

