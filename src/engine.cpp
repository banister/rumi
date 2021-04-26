#include "engine.h"
#include "port_finder.h"
#include "bpf_device.h"
#include "vendor/cxxopts.h"

#include <fmt/core.h>

namespace
{
    bool matchesPacket(const PacketView &packet, const std::vector<std::string> &appNames)
    {
        return std::any_of(appNames.begin(), appNames.end(), [&](const auto &str) {
            return PortFinder::ports({str}, packet.ipVersion()).contains(packet.sourcePort());
        });
    }

    void displayPacket(const PacketView &packet)
    {
        static const char *ipv6FormatString = "{:.20} {} {}.{} > {}.{}\n";
        static const char *ipv4FormatString = "{:.20} {} {}:{} > {}:{}\n";

        const char *formatString = packet.isIpv6() ? ipv6FormatString : ipv4FormatString;
        const auto path{PortFinder::portToPath(packet.sourcePort(), packet.ipVersion())};

        fmt::print(formatString, path, packet.transportName(), packet.sourceAddress(), packet.sourcePort(),
                   packet.destAddress(), packet.destPort());

        ::fflush(stdout);
    }

    int analyzeTraffic(const std::vector<std::string> &appNames)
    {
        auto bpfDevice = BpfDevice::create("en0");

        if(!bpfDevice)
        {
            std::cerr << "Could not load bpf device\n";
            return -1;
        }

        for (;;)
        {
            bpfDevice->onPacketReceived([&](const PacketView &packet) {
                if (packet.hasTransport())
                {
                    if (appNames.empty())
                        displayPacket(packet);
                    // If any app names are provided, only
                    // display a packet if it matches one of those names
                    else
                    {
                        if (matchesPacket(packet, appNames))
                            displayPacket(packet);
                    }
                }
            });
        }
    }
}

int Engine::start(int argc, char **argv)
{
    cxxopts::Options options{"Columbo", "Per-app traffic analyzer"};

    options.allow_unrecognised_options();
    options.add_options()
        ("h,help", "Display this help message.")
        ("i,interface", "The interfaces to listen on.", cxxopts::value<std::vector<std::string>>())
        ("a,analyze", "Analyze traffic.",cxxopts::value<bool>()->default_value("true"))
        ("s,sockets", "Show socket information.");

    auto result = options.parse(argc, argv);

    const auto &unmatched = result.unmatched();

    const std::vector<std::string> appNames{unmatched.begin(), unmatched.end()};

    if(result.count("help"))
    {
        std::cout << options.help();
        return 0;
    }

    if(result.count("sockets"))
    {
        std::cout << "chosen sockets!\n";
        return 0;
    }

    if(result["analyze"].as<bool>())
    {
        return analyzeTraffic(appNames);
    }

    for(auto &i : result.unmatched())
    {
        std::cout << "unmatched args are " << i << "\n";
    }

    return 1;
}
