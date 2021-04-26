#pragma once

#include "common.h"
#include "packet.h"

class Engine
{
public:
    virtual ~Engine() = default;

protected:
    void displayPacket(const PacketView &packet);

protected:
    virtual void showTraffic(const std::vector<std::string> &appNames) = 0;
    virtual void showConnections(const std::vector<std::string> &appNames) = 0;
    virtual std::string portToPath(std::uint16_t, IPVersion ipVersion) = 0;
};
