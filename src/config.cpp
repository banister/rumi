#include "config.h"

Config::Config(const cxxopts::ParseResult &result)
: _verbose{result["verbose"].as<bool>()}
{
    extractProcesses("process", result, _processes);
    extractProcesses("parent", result, _parentProcesses);
    decideIpVersion(result);
    setDisplayColumns(result);
    setFormatString(result);
}

void Config::extractProcesses(const std::string &optionName, const cxxopts::ParseResult &result, SelectedProcesses &selectedProcesses)
{
    const static std::regex pidRegex{R"([0-9]+)", std::regex::ECMAScript};

    if(result.count(optionName))
    {
        // Contains both pids and names
        const auto &processes = result[optionName].as<std::vector<std::string>>();
        for(const auto &process : processes)
        {
            std::smatch match;
            if (std::regex_match(process, match, pidRegex))
                selectedProcesses._pids.insert(std::stoi(process));
            else
                selectedProcesses._names.insert(process);
        }
    }
}

void Config::decideIpVersion(const cxxopts::ParseResult &result)
{
    // If both specified, then use both
    if(result["inet"].as<bool>() && result["inet6"].as<bool>())
        _ipVersion = IPVersion::Both;
    // Otherwise just ipv4 (if specified)
    else if(result["inet"].as<bool>())
        _ipVersion = IPVersion::IPv4;
    // Or just ipv6 (if specified)
    else if(result["inet6"].as<bool>())
        _ipVersion = IPVersion::IPv6;
    else
        // Default to both ipv4 and ipv6
        _ipVersion = IPVersion::Both;
}

void Config::setDisplayColumns(const cxxopts::ParseResult &result)
{
    if(result.count("cols"))
    {
        const auto &colVec = result["cols"].as<std::vector<std::string>>();
        _displayColumns = colVec;
    }
}

void Config::setFormatString(const cxxopts::ParseResult &result)
{
    if(result.count("format"))
    {
        _formatString = result["format"].as<std::string>();
    }
}
