#pragma once

#include <libproc.h>  // for proc_pidpath()
#include <set>
#include "common.h"

namespace PortFinder
{

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

std::string pidToPath(pid_t);

// Thin wrapper around socket_info for convenience
class Connection
{
public:
    explicit Connection(socket_info pSocketInfo, pid_t pid)
    : _socketInfo{std::move(pSocketInfo)}
    , _pid{pid}
    {}

    //Ipv4
    std::uint32_t localIp4() const {return isIpv4() ? ntohl(inetInfo().insi_laddr.ina_46.i46a_addr4.s_addr) : 0;}
    std::uint32_t remoteIp4() const {return isIpv4() ? ntohl(inetInfo().insi_faddr.ina_46.i46a_addr4.s_addr) : 0;}
    // Ipv6 (return by reference as the members are quite large)
    const auto& localIp6() const {return isIpv6() ? inetInfo().insi_laddr.ina_6.s6_addr : _nullIpv6Address;}
    const auto& remoteIp6() const {return isIpv6() ? inetInfo().insi_faddr.ina_6.s6_addr : _nullIpv6Address;}
    bool isIpv6AnyAddress() const;
    std::uint16_t localPort() const {return ntohs(inetInfo().insi_lport);}
    std::uint32_t remotePort() const {return ntohs(inetInfo().insi_fport);}
    int protocol() const {return _socketInfo.soi_protocol;}
    bool isIpv4() const {return isIpVersion(INI_IPV4);}
    bool isIpv6() const {return isIpVersion(INI_IPV6);}
    pid_t pid() const {return _pid;}
    std::string path() const {return pidToPath(_pid);}

    std::string toString() const;

    friend std::ostream& operator<<(std::ostream& os, const Connection &conn)
    {
        os << conn.toString();
        return os;
    }
private:
    std::uint8_t isIpVersion(std::uint8_t flag) const {return inetInfo().insi_vflag & flag;}
    const in_sockinfo& inetInfo() const {return _socketInfo.soi_proto.pri_in;}
private:
    unsigned char _nullIpv6Address[16]{};
    socket_info _socketInfo;
    pid_t _pid;
};
    // The maximum number of PIDs we support
enum { maxPids = 16384 };

std::set<pid_t> pids(const std::vector<std::string> &paths);
PortSet ports(const std::set<pid_t> &pids, IPVersion ipVersion);
PortSet ports(const std::vector<std::string> &paths, IPVersion ipVersion);
std::set<AddressAndPort> addresses4(const std::vector<std::string> &paths);
pid_t portToPid(std::uint16_t port, IPVersion ipVersion=IPv4);
std::string pidToPath(pid_t);
std::string portToPath(std::uint16_t port, IPVersion ipVersion);
std::vector<Connection> connections(const std::set<pid_t> &pids, IPVersion ipVersion);
std::vector<Connection> connections(const std::vector<std::string> &paths, IPVersion ipVersion);
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
