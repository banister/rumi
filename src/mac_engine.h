#pragma once

#include "common.h"
#include "engine.h"
#include "bpf_device.h"

class MacEngine : public Engine
{
public:
    using Engine::Engine;

protected:
    virtual void showTraffic(const std::vector<std::string> &appNames) override;
    virtual void showConnections(const std::vector<std::string> &appNames) override;
    virtual std::string portToPath(std::uint16_t, IPVersion ipVersion) override;
    bool matchesPacket(const PacketView &packet, const std::vector<std::string> &appNames);
};
