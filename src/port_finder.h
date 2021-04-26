#pragma once

#include <libproc.h>  // for proc_pidpath()
#include <set>
#include "common.h"
class AddressAndPort
{
public:
    AddressAndPort(std::uint32_t ip, std::uint16_t port)
    : _ip{ip}
    , _port{port}
    {}

    AddressAndPort(const AddressAndPort &other)
    : AddressAndPort(other._ip, other._port)
    {}

    auto operator<=>(const AddressAndPort&) const = default;
public:
    std::uint32_t ip() const {return _ip;}
    std::uint16_t port() const {return _port;}
private:
    std::uint32_t _ip;
    std::uint16_t _port;
};

namespace PortFinder
{
    // The maximum number of PIDs we support
enum { maxPids = 16384 };

std::set<pid_t> pids(const std::vector<std::string> &paths);
PortSet ports(const std::set<pid_t> &pids, IPVersion ipVersion);
PortSet ports(const std::vector<std::string> &paths, IPVersion ipVersion);
std::set<AddressAndPort> addresses4(const std::vector<std::string> &paths);
pid_t portToPid(std::uint16_t port, IPVersion ipVersion=IPv4);
std::string pidToPath(pid_t);
std::string portToPath(std::uint16_t port, IPVersion ipVersion);
bool matchesPath(const std::vector<std::string> &paths, pid_t pid);

template <typename Func_T>
pid_t pidFor(Func_T func)
{
    int totalPidCount = 0;
    std::vector<pid_t> allPidVector;
    allPidVector.resize(maxPids);

    // proc_listallpids() returns the total number of PIDs in the system
    // (assuming that maxPids is > than the total PIDs, otherwise it returns maxPids)
    totalPidCount = proc_listallpids(allPidVector.data(), maxPids * sizeof(pid_t));

    for (int i = 0; i != totalPidCount; ++i)
    {
        pid_t pid = allPidVector[i];

        // Add the PID to our set if matches one of the paths
        if(func(pid))
            return pid;
    }

    return 0;
}

template <typename Func_T>
std::set<pid_t> pidsFor(Func_T func)
{
    int totalPidCount = 0;
    std::set<pid_t> pidsForPaths;
    std::vector<pid_t> allPidVector;
    allPidVector.resize(maxPids);

    // proc_listallpids() returns the total number of PIDs in the system
    // (assuming that maxPids is > than the total PIDs, otherwise it returns maxPids)
    totalPidCount = proc_listallpids(allPidVector.data(), maxPids * sizeof(pid_t));

    for(int i = 0; i != totalPidCount; ++i)
    {
        pid_t pid = allPidVector[i];

        // Add the PID to our set if matches one of the paths
        if(func(pid))
            pidsForPaths.insert(pid);
    }

    return pidsForPaths;
}
}
