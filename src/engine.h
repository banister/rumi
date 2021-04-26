#pragma once

#include "common.h"
#include "packet.h"

class Engine
{
public:
    virtual ~Engine() = default;

public:
    void start(int argc, char **argv);

protected:
    void displayPacket(const PacketView &packet, const std::string &appPath);

protected:
    virtual void showTraffic(const std::vector<std::string> &appNames) = 0;
    virtual void showConnections(const std::vector<std::string> &appNames) = 0;
};
