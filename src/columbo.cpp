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
#include <fmt/core.h>
#include "engine.h"

#include "port_finder.h"
#include "bpf_device.h"

int main(int argc, char** argv)
{

    return Engine{}.start(argc, argv);

/*     popl::OptionParser op{"Allowed options"};
    auto helpOption = op.add<popl::Switch>("h", "help", "Display this help message.");
    auto connectionsOption = op.add<popl::Switch>("c", "connections", "Just display active connections.");
    auto snifferOption = op.add<popl::Switch>("s", "sniffer", "Display traffic for matching apps.");
    auto interfaceOption = op.add<popl::Value<std::string>>("i", "interface", "The interface(s) to listen on.");

    op.parse(argc, argv);

    // print auto-generated help message
    if(helpOption->is_set())
    {
        std::cout << op << "\n";
        return 0;
    }

    std::cout << "non option args\n";
    for(auto &nonOpt : op.non_option_args())
        std::cout << nonOpt << std::endl;

    std::cout << "interface args\n";
    for(auto &opt : interfaceOption->values())
        std::cout << opt << std::endl;

    return 1;

    auto bpfDevice = BpfDevice::create("en0");

    if(!bpfDevice)
    {
        std::cerr << "Could not load bpf device\n";
        return -1;
    }


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
    */
    return 0;
}
