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
        bpfDevice->onPacketReceived([&](const std::variant<Packet, Packet6> &packet)
        {
            if(std::holds_alternative<Packet>(packet))
                std::cout << std::get<Packet>(packet).toString() << std::endl;
            else
                std::cout << std::get<Packet6>(packet).toString() << std::endl;

/*             if(ntohs(eh->ether_type) == ETHERTYPE_IPV6)
            {
                char src_addr[INET6_ADDRSTRLEN];
                char dst_addr[INET6_ADDRSTRLEN];
                struct ip6_hdr *ip = (struct ip6_hdr *)((long)eh + sizeof(struct ether_header));
                struct tcphdr *tcp = (struct tcphdr *)((long)ip + sizeof(struct ip6_hdr)); //(ip-> ip6_plen));
                inet_ntop(AF_INET6, &ip->ip6_src, src_addr, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &ip->ip6_dst, dst_addr, INET6_ADDRSTRLEN);

                if (ip->ip6_nxt == IPPROTO_TCP || ip->ip6_nxt == IPPROTO_UDP)
                {
                    const auto sourcePort{ntohs(tcp->th_sport)};
                    const auto destPort{ntohs(tcp->th_dport)};

                    if (searchStrings.empty())
                    {
                        const auto path{PortFinder::pidToPath(PortFinder::pidForPort(sourcePort, IPv6))};
                        printf("%.30s %s.%d > %s.%d\n", path.c_str(), src_addr, sourcePort, dst_addr, destPort);
                    }
                    else
                    {
                        bool stringMatched = std::any_of(searchStrings.begin(), searchStrings.end(), [&](const auto &str) {
                            return PortFinder::ports({str}, IPv6).contains(sourcePort);
                        });

                        if (stringMatched)
                        {
                            const auto path{PortFinder::pidToPath(PortFinder::pidForPort(sourcePort, IPv6))};
                            printf("%.30s %s.%d > %s.%d\n", path.c_str(), src_addr, sourcePort, dst_addr, destPort);
                        }
                    }
                    fflush(stdout);
                }
            }
            else if (ntohs(eh->ether_type) == ETHERTYPE_IP)
            {
                struct ip *ip = (struct ip *)((long)eh + sizeof(struct ether_header));
                struct tcphdr *tcp = (struct tcphdr *)((long)ip + (ip->ip_hl * 4));

                if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP)
                {
                    const auto sourcePort{ntohs(tcp->th_sport)};
                    const auto destPort{ntohs(tcp->th_dport)};
                    const std::string sourceAddr{inet_ntoa(ip->ip_src)};
                    const std::string destAddr{inet_ntoa(ip->ip_dst)};

                    if (searchStrings.empty())
                    {
                        const auto path{PortFinder::pidToPath(PortFinder::pidForPort(sourcePort, IPv4))};
                        printf("%.30s %s:%d > %s:%d\n", path.c_str(), sourceAddr.c_str(), sourcePort, destAddr.c_str(), destPort);
                    }
                    else
                    {
                        bool stringMatched = std::any_of(searchStrings.begin(), searchStrings.end(), [&](const auto &str) {
                            return PortFinder::ports({str}, IPv4).contains(sourcePort);
                        });

                        if (stringMatched)
                        {
                            const auto path{PortFinder::pidToPath(PortFinder::pidForPort(sourcePort, IPv4))};
                            printf("%.30s %s:%d > %s:%d\n", path.c_str(), sourceAddr.c_str(), sourcePort, destAddr.c_str(), destPort);
                        }
                    }
                    fflush(stdout);
                }
            }
 */        });
    }
    return 0;
}
