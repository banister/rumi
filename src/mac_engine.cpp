#include "mac_engine.h"
#include "port_finder.h"
#include "bpf_device.h"

bool MacEngine::matchesPacket(const PacketView &packet, const std::vector<std::string> &appNames)
{
    return std::any_of(appNames.begin(), appNames.end(), [&](const auto &str) {
        return PortFinder::ports({str}, packet.ipVersion()).contains(packet.sourcePort());
    });
}

void MacEngine::showConnections(const std::vector<std::string> &appNames)
{
}

void MacEngine::showTraffic(const std::vector<std::string> &appNames)
{
    auto bpfDevice = BpfDevice::create("en0");

    if(!bpfDevice)
        throw std::runtime_error("could not load bpf device");

    while(true)
    {
        bpfDevice->onPacketReceived([&, this](const PacketView &packet) {
            auto appPath{PortFinder::portToPath(packet.sourcePort(), packet.ipVersion())};
             if(packet.hasTransport())
            {
                if(appNames.empty())
                    displayPacket(packet, appPath);
                // If any app names are provided, only
                // display a packet if it matches one of those names
                else
                {
                    if(matchesPacket(packet, appNames))
                        displayPacket(packet, appPath);
                }
            }
        });
    }
}

