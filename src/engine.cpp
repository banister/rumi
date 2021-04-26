#include "engine.h"
#include "packet.h"
#include <fmt/core.h>

void Engine::displayPacket(const PacketView &packet)
{
    static const char *ipv6FormatString = "{:.20} {} {}.{} > {}.{}\n";
    static const char *ipv4FormatString = "{:.20} {} {}:{} > {}:{}\n";

    const char *formatString = packet.isIpv6() ? ipv6FormatString : ipv4FormatString;
    const auto path{portToPath(packet.sourcePort(), packet.ipVersion())};

    fmt::print(formatString, path, packet.transportName(), packet.sourceAddress(), packet.sourcePort(),
               packet.destAddress(), packet.destPort());

    ::fflush(stdout);
}

