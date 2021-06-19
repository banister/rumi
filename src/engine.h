#pragma once

#include "common.h"
#include "packet.h"
#include "vendor/cxxopts.h"

class Engine
{
public:
    class Config;

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

class Engine::Config
{
public:
    Config(const cxxopts::ParseResult &result);

public:
    bool verbose() const {return _verbose;}
    IPVersion ipVersion() const {return _ipVersion;}
    const std::set<std::string> &processNames() const {return _processNames;}
    const std::set<pid_t> &processPids() const {return _processPids;}

    // indicates whether user specified any proocesses to watch on CLI
    // if this is true, should indicate that we must skip anything else
    bool processesProvided() const {return !_processNames.empty() || !_processPids.empty();}

private:
    // Extract the processes we want to observe (both by pid and names)
    void extractProcesses(const cxxopts::ParseResult &result);
    // The IP version(s) we're interested in
    void decideIpVersion(const cxxopts::ParseResult &result);

private:
    bool _verbose{};
    IPVersion _ipVersion{};
    std::set<std::string> _processNames;
    std::set<pid_t> _processPids;
};
