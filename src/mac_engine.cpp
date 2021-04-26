#include "mac_engine.h"
#include "port_finder.h"
#include "bpf_device.h"
#include "vendor/cxxopts.h"

MacEngine::MacEngine(int argc, char **argv)
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
        return;
    }

    if(result.count("sockets"))
    {
        std::cout << "chosen sockets!\n";
        return;
    }

    if(result["analyze"].as<bool>())
    {
        showTraffic(appNames);
        return;
    }
}

bool MacEngine::matchesPacket(const PacketView &packet, const std::vector<std::string> &appNames)
{
    return std::any_of(appNames.begin(), appNames.end(), [&](const auto &str) {
        return PortFinder::ports({str}, packet.ipVersion()).contains(packet.sourcePort());
    });
}

void MacEngine::showTraffic(const std::vector<std::string> &appNames)
{
    auto bpfDevice = BpfDevice::create("en0");

    //if(!bpfDevice)
        throw std::runtime_error("could not load bpf device");

    while(true)
    {
        bpfDevice->onPacketReceived([&, this](const PacketView &packet) {
            if(packet.hasTransport())
            {
                if(appNames.empty())
                    displayPacket(packet);
                // If any app names are provided, only
                // display a packet if it matches one of those names
                else
                {
                    if(matchesPacket(packet, appNames))
                        displayPacket(packet);
                }
            }
        });
    }
}

std::string MacEngine::portToPath(std::uint16_t port, IPVersion ipVersion)
{
    return PortFinder::portToPath(port, ipVersion);
}

void MacEngine::showConnections(const std::vector<std::string> &appNames)
{
}


