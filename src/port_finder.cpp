#include <filesystem>
#include "common.h"
#include "port_finder.h"
#include "ip_address.h"

namespace fs = std::filesystem;

bool PortFinder::Connection::isIpv6AnyAddress() const
{
    if(isIpv4()) return false;

    const auto &in6addr{inetInfo().insi_laddr.ina_6.s6_addr};
    return std::all_of(std::begin(in6addr), std::end(in6addr), [](auto val)
    {
        return val == 0;
    });
}

std::string PortFinder::Connection::buildString(bool verbose) const
{
    const char *formatString = isIpv4() ? "{} {}:{} -> {}:{} {}" : "{} {}.{} -> {}.{} {}";

    const std::string protocol = this->protocol() == IPPROTO_TCP ? "TCP" : "UDP";
    const std::string filePath = verbose ? path() : static_cast<std::string>(fs::path(path()).filename());

    if(isIpv4())
    {
        return fmt::format(formatString, protocol, IPv4Address{localIp4()}.toString(),
            localPort(), IPv4Address{remoteIp4()}.toString(), remotePort(), filePath);
    }
    else
    {
        return fmt::format(formatString, protocol, IPv6Address{localIp6()}.toString(),
            localPort(), IPv6Address{remoteIp6()}.toString(), remotePort(), filePath);
    }
}

namespace
{
template <typename Func_T>
void connectionsForPid(pid_t pid, IPVersion ipVersion, Func_T func)
{
    // Get the buffer size needed
    int size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
    if(size <= 0)
        return;

    std::vector<proc_fdinfo> fds;
    fds.resize(size / sizeof(proc_fdinfo));
    // Get the file descriptors
    size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(), fds.size() * sizeof(proc_fdinfo));
    fds.resize(size / sizeof(proc_fdinfo));

    for(const auto &fd : fds)
    {
        if(fd.proc_fdtype != PROX_FDTYPE_SOCKET)
            continue;   // Don't care about anything besides sockets

        socket_fdinfo socketFdInfo{};
        size = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO,
                              &socketFdInfo, sizeof(socketFdInfo));
        if(size != sizeof(socketFdInfo))
        {
/*             qWarning() << "Failed to inspect descriptor" << fd.proc_fd << "of"
                << pid << "- got size" << size << "- expected" << sizeof(socketFdInfo);
 */            continue;
        }

        // Use an OOP wrapper for convenience
        const PortFinder::Connection connection{socketFdInfo.psi, pid};

        // Don't care about anything other than TCP/UDP.
        // It seems that TCP sockets may sometimes be indicated with
        // soi_kind==SOCKINFO_IN instead of SOCKINFO_TCP.
        // we don't use anything from the TCP-specific socket info so this is
        // fine, identify sockets by checking the IP protocol.
        if(!(connection.protocol() == IPPROTO_TCP || connection.protocol() == IPPROTO_UDP))
            continue;

        if(ipVersion == IPv4 && connection.isIpv4())
        {
            // The local address can be 0, but the port must be valid
            if(connection.localPort() > 0)
                func(connection);
        }
        else if(connection.isIpv6())
        {
            // Store an IPv6 socket if it's the "any" address (and has a valid
            // port)
            if(ipVersion == IPv4)
            {
                if(connection.isIpv6AnyAddress() && connection.localPort() > 0)
                    func(connection);
            }
            else if(ipVersion == IPv6)
            {
                if(connection.localPort() > 0)
                    func(connection);
            }
        }
    }
}
}

bool PortFinder::matchesPath(const std::set<std::string> &paths, pid_t pid)
{
    std::string appPath = pidToPath(pid);

    return std::any_of(paths.begin(), paths.end(),
        [&appPath](const std::string &prefix) {
            return appPath.find(prefix) != std::string::npos;
        });
}

std::string PortFinder::pidToPath(pid_t pid)
{
    char path[PATH_MAX]{};
    proc_pidpath(pid, path, sizeof(path));

    // Wrap in std::string for convenience
    return std::string{path};
}

pid_t PortFinder::portToPid(std::uint16_t port, IPVersion ipVersion)
{
    return pidFor([&](const auto &pid) {
        std::set<std::uint16_t> ports;
        connectionsForPid(pid, ipVersion, [&](const auto &connection) {
            ports.insert(connection.localPort());
        });
        return ports.contains(port);
    });
}

std::set<pid_t> PortFinder::pids(const std::set<std::string>& paths)
{
    return pidsFor([&](const auto &pid) { return matchesPath(paths, pid); });
}

PortSet PortFinder::ports(const std::set<pid_t> &pids, IPVersion ipVersion)
{
    std::set<std::uint16_t> ports;
    for(const auto &pid : pids)
        connectionsForPid(pid, ipVersion, [&](const auto &connection) {
            if(connection.isIpv4())
                ports.insert(connection.localPort());
            else if(connection.isIpv6())
                ports.insert(connection.localPort());
        });

    return ports;
}

PortSet PortFinder::ports(const std::set<std::string>& paths, IPVersion ipVersion)
{
    return ports(pids(paths), ipVersion);
}

std::set<PortFinder::AddressAndPort> PortFinder::addresses4(const std::set<std::string> &paths)
{
    std::set<AddressAndPort> addresses;
    for(const auto &pid : pids(paths))
        connectionsForPid(pid, IPv4, [&addresses](const auto &connection) {
            addresses.insert({static_cast<std::uint32_t>(connection.localIp4()), connection.localPort()});
        });

    return addresses;
}

std::vector<PortFinder::Connection> PortFinder::connections(const std::set<std::string> &paths, IPVersion ipVersion)
{
    return connections(pids(paths), ipVersion);
}

std::vector<PortFinder::Connection> PortFinder::connections(const std::set<pid_t> &pids, IPVersion ipVersion)
{
    std::vector<Connection> connections;
    for(const auto &pid : pids)
        connectionsForPid(pid, ipVersion, [&](const auto &connection) {
            connections.push_back(connection);
        });

    return connections;
}

std::string PortFinder::portToPath(std::uint16_t port, IPVersion ipVersion)
{
    return pidToPath(portToPid(port, ipVersion));
}

