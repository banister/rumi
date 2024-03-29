#include "mac_engine.h"
#include "port_finder.h"
#include "bpf_device.h"
#include "auditpipe.h"
#include "view.h"

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
    std::set<pid_t> allProcessPids(const Config& config)
    {
        auto allPids = config.processes().pids();
        // Convert process search strings to pids
        auto pids = PortFinder::pids(config.processes().names());
        allPids.merge(pids);

        return allPids;
    }

    // Do one of the search strings match the process name?
    bool nameMatches(const std::set<std::string> &searchStrings, const std::string &processName)
    {
        auto iter = std::find_if(searchStrings.begin(), searchStrings.end(), [&](const std::string &search)
        {
            return (processName.rfind(search) == std::string::npos ? false : true);
        });

        if(iter != searchStrings.end())
            return true;

        return false;
    }

    std::set<pid_t> allParentProcessPids(const Config& config)
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
        // Skip packets with the unwanted ipVersion
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
                // FIXME: to explicitly match on processNames NOT just pid
                // coz there MAY be a race when it comes to looking up pids from names
                // the pid might not be available at the point we look it up.
                // This may nto be an issue here with packet sniffing, but is definitely an issue
                // when tracing process startups in showExec
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
        if(config.processesProvided() &&
           !allProcessPids(config).contains(event.pid) &&
           !allParentProcessPids(config).contains(event.ppid) &&
           // Need an explicit match on process names (rather than just relying on name -> pid conversion
           // in allProcessPids()) because the process might not actually exist at this point, the audit
           // pipe indicates process is starting but not necessary started.
           !nameMatches(config.processes().names(), basename(event.path)))
        {
            return;
        }

        View::Exec<decltype(event)>{event, config}.render();
    });

    // Infinite loop
    auditPipe.receive();
}

