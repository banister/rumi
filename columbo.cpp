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

int main(int argc, char** argv)
{
    using std::cout;
    using std::vector;

    auto bpfDevice = BpfDevice::create("en0");

    if(!bpfDevice)
    {
        std::cerr << "Could not load bpf device\n";
        return -1;
    }

    std::cout << "Successfully created bpf device!\n";

    vector<std::string> searchStrings;
    searchStrings.reserve(argc);

    if(argc > 1)
        for(int i=1; i<argc; ++i) searchStrings.emplace_back(argv[i]);

    while(true)
    {
        bpfDevice->onPacketReceived([&](const PacketView &packet)
        {
            if(packet.hasTransport())
            {
                if(searchStrings.empty())
                {
                    const auto path{PortFinder::pidToPath(PortFinder::pidForPort(packet.sourcePort(), packet.ipVersion()))};
                    printf("%.30s %s %s.%d > %s.%d\n", path.c_str(), packet.transportName().c_str(),
                        packet.sourceAddress().c_str(), packet.sourcePort(), packet.destAddress().c_str(), packet.destPort());
                }
                else
                {
                    bool stringMatched = std::any_of(searchStrings.begin(), searchStrings.end(), [&](const auto &str) {
                        return PortFinder::ports({str}, packet.ipVersion()).contains(packet.sourcePort());
                    });

                    if(stringMatched)
                    {
                        const auto path{PortFinder::pidToPath(PortFinder::pidForPort(packet.sourcePort(), packet.ipVersion()))};
                        printf("%.30s %s %s.%d > %s.%d\n", path.c_str(), packet.transportName().c_str(),
                            packet.sourceAddress().c_str(), packet.sourcePort(), packet.destAddress().c_str(), packet.destPort());
                    }
                }
                fflush(stdout);
            }
        });
    }
    return 0;
}
