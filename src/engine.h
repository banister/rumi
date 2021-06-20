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
    class SelectedProcesses
    {
    public:
        const std::set<std::string> &names() const {return _names;}
        const std::set<pid_t> &pids() const {return _pids;}
        bool empty() const {return _names.empty() && _pids.empty();}

    private:
        std::set<std::string> _names;
        std::set<pid_t> _pids;

    private:
        friend class Config;
    };
public:
    Config(const cxxopts::ParseResult &result);

public:
    bool verbose() const {return _verbose;}
    IPVersion ipVersion() const {return _ipVersion;}
    const SelectedProcesses &processes() const {return _processes;}
    const SelectedProcesses &parentProcesses() const {return _parentProcesses;}
    const std::set<std::string> &displayColumns() const {return _displayColumns;}

    // indicates whether user specified any proocesses to watch on CLI
    // if this is true, should indicate that we must skip anything else
    bool processesProvided() const {return !_processes.empty() || !_parentProcesses.empty();}

private:
    // Extract the processes we want to observe (both by pid and names)
    void extractProcesses(const std::string &optionName, const cxxopts::ParseResult &result, SelectedProcesses &selectedProcesses);
    // The IP version(s) we're interested in
    void decideIpVersion(const cxxopts::ParseResult &result);
    // The display columns requested - used for rendering output
    void setDisplayColumns(const cxxopts::ParseResult &result);

private:
    bool _verbose{};
    IPVersion _ipVersion{};
    SelectedProcesses _processes;
    SelectedProcesses _parentProcesses;
    std::set<std::string> _displayColumns;
};
