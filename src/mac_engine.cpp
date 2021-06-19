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

    std::set<pid_t> allProcessPids(const Engine::Config& config)
    {
        auto allPids = config.processPids();
        // Convert process names to pids
        auto pids = PortFinder::pids(config.processNames());

        allPids.merge(pids);

        return allPids;
    }

    bool matchesPacket(const PacketView &packet, const std::set<pid_t> &pids)
    {
        return PortFinder::ports(pids, packet.ipVersion()).count(packet.sourcePort());
    }
}

void MacEngine::showConnections(const Config &config)
{
    std::string(PortFinder::Connection::*fptr)() const = nullptr;
    fptr = config.verbose() ? &PortFinder::Connection::toVerboseString : &PortFinder::Connection::toString;

    auto showConnectionsForIPVersion = [&, this](IPVersion ipVersion)
    {
        std::cout << ipVersionToString(ipVersion) << "\n==\n";
        // Must run cmb as sudo to show all sockets, otherwise some are missed
        const auto connections = PortFinder::connections(config.processNames(), ipVersion);
        for(const auto &conn : connections)
            std::cout << (conn.*fptr)() << "\n";
    };

    if(config.ipVersion() == IPVersion::Both)
    {
        showConnectionsForIPVersion(IPv4);
        showConnectionsForIPVersion(IPv6);
    }
    else
        showConnectionsForIPVersion(config.ipVersion());
}

void MacEngine::showTraffic(const Config &config)
{
    BpfDevice bpfDevice{"en0"};

    // FIXME: refactor to follow pattern in AuditPipe
    while(true)
    {
        bpfDevice.onPacketReceived([&, this](const PacketView &packet) {
            const std::string fullPath{PortFinder::portToPath(packet.sourcePort(), packet.ipVersion())};
            const std::string path = config.verbose() ? fullPath : basename(fullPath);

            const auto pidsToMatch = allProcessPids(config);

            if(config.ipVersion() != IPVersion::Both)
                // Skip packets with unwanted ipVersion
                if(packet.ipVersion() != config.ipVersion())
                    return;

             if(packet.hasTransport())
             {
                if(pidsToMatch.empty())
                    displayPacket(packet, path);
                // If any app names are provided, only
                // display a packet if it matches one of those names
                else
                {
                    if(matchesPacket(packet, pidsToMatch))
                        displayPacket(packet, path);
                }
            }
        });
    }
}

void MacEngine::showExec(const Config &config)
{
    AuditPipe auditPipe;

    // Execute this callback whenever a process starts up
    auditPipe.onProcessStarted([&, this](const auto &event)
    {
        // Need to re-evaluate each time a process starts
        const auto pidsToMatch = allProcessPids(config);

        if(config.processesProvided() && std::find(pidsToMatch.begin(), pidsToMatch.end(), event.ppid) == pidsToMatch.end())
            return;

        std::cout << "pid: " << event.pid << " ppid: " << event.ppid << " - ";
        std::cout << (config.verbose() ? event.path : basename(event.path)) << " ";

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
    auditPipe.receive();
}

