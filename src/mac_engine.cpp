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

    // Get the list of all process pids that we care about based on user config.
    // This includes the specific numeric pids given on the CLI (via -p <pid>)
    // and also includes the process search strings (-p <search string>) converted to pids
    std::set<pid_t> allProcessPids(const Engine::Config& config)
    {
        auto allPids = config.processes().pids();
        // Convert process search strings to pids
        auto pids = PortFinder::pids(config.processes().names());
        allPids.merge(pids);

        return allPids;
    }

    std::set<pid_t> allParentProcessPids(const Engine::Config& config)
    {
        auto allPids = config.parentProcesses().pids();
        // Convert process search strings to pids
        auto pids = PortFinder::pids(config.parentProcesses().names());
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

    auto showConnectionsForIPVersion = [&](IPVersion ipVersion)
    {
        std::cout << ipVersionToString(ipVersion) << "\n==\n";
        // Must run cmb as sudo to show all sockets, otherwise some are missed
        const auto connections = PortFinder::connections(allProcessPids(config), ipVersion);
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

    bpfDevice.onPacketReceived([&](const PacketView &packet)
    {
        if(config.ipVersion() != IPVersion::Both)
        // Skip packets with unwanted ipVersion
        if(packet.ipVersion() != config.ipVersion())
            return;

        // We only care about TCP and UDP
        if(packet.hasTransport())
        {
            const std::string fullPath{PortFinder::portToPath(packet.sourcePort(), packet.ipVersion())};
            const std::string path = config.verbose() ? fullPath : basename(fullPath);

            // If we want to observe specific processes (-p)
            // then limit to showing only packets from those processes
            if(config.processesProvided())
            {
                if(matchesPacket(packet, allProcessPids(config)))
                    displayPacket(packet, path);
            }

            // Otherwise show everything
            else
            {
                displayPacket(packet, path);
            }
        }
    });

    // Infinite loop
    bpfDevice.receive();
}

void MacEngine::showExec(const Config &config)
{
    AuditPipe auditPipe;

    // Execute this callback whenever a process starts up
    auditPipe.onProcessStarted([&](const auto &event)
    {
        // Don't show any processes if the user has said they're only
        // interested in specific processes AND we currently have no processes
        // that match the ones they care about
        if(config.processesProvided() && !allProcessPids(config).contains(event.pid) && !allParentProcessPids(config).contains(event.ppid))
            return;

        // FIXME:
        // For process names compare against the actual event.path - don't convert to pids first
        // (as we do currentlyl) - as the current approach doesn't see so relilable, may be a race condition
        // which means we don't always get all matching processes. cf rumi -p route which
        // doesn't appear to match anything

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

