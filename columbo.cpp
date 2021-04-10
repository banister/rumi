#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <iostream>

#include "port_finder.h"
#include "bpf_device.h"

void displayPacket(const PacketView &packet)
{
    static const char *ipv6FormatString = "%.30s %s %s.%d > %s.%d\n";
    static const char *ipv4FormatString = "%.30s %s %s:%d > %s:%d\n";

    const char *formatString = packet.isIpv6() ? ipv6FormatString : ipv4FormatString;
    const auto path{PortFinder::portToPath(packet.sourcePort(), packet.ipVersion())};

    printf(formatString, path.c_str(), packet.transportName().c_str(),
        packet.sourceAddress().c_str(), packet.sourcePort(),
        packet.destAddress().c_str(), packet.destPort());

    fflush(stdout);
}

class AppNames
{
public:
    explicit AppNames(int argc, char** argv);

public:
    bool isEmpty() const {return _searchStrings.empty();}
    bool matchesPacket(const PacketView &packet) const;

private:
    std::vector<std::string> _searchStrings;
};

AppNames::AppNames(int argc, char** argv)
{
    _searchStrings.reserve(argc);

    if(argc <= 1)
        return;

    for(int i=1; i<argc; ++i)
        _searchStrings.emplace_back(argv[i]);
}

bool AppNames::matchesPacket(const PacketView &packet) const
{
    return std::any_of(_searchStrings.begin(), _searchStrings.end(), [&](const auto &str) {
        return PortFinder::ports({str}, packet.ipVersion()).contains(packet.sourcePort());
    });
}

int main(int argc, char** argv)
{
    auto bpfDevice = BpfDevice::create("en0");

    if(!bpfDevice)
    {
        std::cerr << "Could not load bpf device\n";
        return -1;
    }

    AppNames appNames{argc, argv};

    for(;;)
    {
        bpfDevice->onPacketReceived([&](const PacketView &packet)
        {
            if(packet.hasTransport())
            {
                if(appNames.isEmpty())
                    displayPacket(packet);
                // If any app names are provided, only
                // display a packet if it matches one of those names
                else
                {
                    if(appNames.matchesPacket(packet))
                        displayPacket(packet);
                }
            }
        });
    }
    return 0;
}
