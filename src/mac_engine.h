#pragma once

#include "common.h"
#include "engine.h"
#include "bpf_device.h"

class MacEngine : public Engine
{
protected:
    virtual void showTraffic(const std::vector<std::string> &appNames, IPVersion ipVersion) override;
    virtual void showConnections(const std::vector<std::string> &appNames, IPVersion ipVersion) override;

private:
    bool matchesPacket(const PacketView &packet, const std::vector<std::string> &appNames);
};
