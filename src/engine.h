#pragma once

#include "common.h"
#include "packet.h"
#include "config.h"

class Config;

class Engine
{
public:
    virtual ~Engine() = default;

public:
    void start(int argc, char **argv);

protected:
    void displayPacket(const PacketView &packet, const std::string &appPath);

protected:
    virtual void showTraffic(const Config &config) = 0;
    virtual void showConnections(const Config &config) = 0;
    virtual void showExec(const Config &config) = 0;
};

