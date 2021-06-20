#include "engine.h"
#include "packet.h"
#include <fmt/core.h>

void Engine::start(int argc, char **argv)
{
    cxxopts::Options options{"rumi", "Runtime ruminations"};

    options.allow_unrecognised_options();
    options.add_options()
        ("h,help", "Display this help message.")
        ("a,analyze", "Analyze traffic.")
        ("s,sockets", "Show socket information.")
        ("e,exec", "Show process execs.")
        ("p,process", "The processes to observe (either pid or name)", cxxopts::value<std::vector<std::string>>())
        ("P,parent", "The parent processes to observe (either pid or name)", cxxopts::value<std::vector<std::string>>())
        ("c,cols", "The display columns to use for output.", cxxopts::value<std::vector<std::string>>())
        ("v,verbose", "Verbose output.",cxxopts::value<bool>()->default_value("false"))
        ("4,inet", "IPv4 only.",cxxopts::value<bool>()->default_value("false"))
        ("6,inet6", "IPv6 only.",cxxopts::value<bool>()->default_value("false"));

    auto result = options.parse(argc, argv);

    // Initialize our config from the CLI options
    Config config{result};

    if(!result.unmatched().empty())
    {
        std::cout << "Error: Unrecognized option: "
            << result.unmatched().front() << "\n\n" << options.help();
    }
    else if(result.count("help"))
    {
        std::cout << options.help();
    }
    else if(result.count("sockets"))
    {
        showConnections(config);
    }
    else if(result["exec"].as<bool>())
    {
        showExec(config);
    }
    else if(result["analyze"].as<bool>())
    {
        showTraffic(config);
    }
    else
    {
        std::cout << "No mode given: specify -a, -s or -e\n\n" << options.help();
    }
}

void Engine::displayPacket(const PacketView &packet, const std::string &appPath)
{
    static const char *ipv6FormatString = "{:.20} {} {}.{} > {}.{}\n";
    static const char *ipv4FormatString = "{:.20} {} {}:{} > {}:{}\n";

    const char *formatString = packet.isIpv6() ? ipv6FormatString : ipv4FormatString;

    fmt::print(formatString, appPath, packet.transportName(), packet.sourceAddress(), packet.sourcePort(),
               packet.destAddress(), packet.destPort());

    ::fflush(stdout);
}

Engine::Config::Config(const cxxopts::ParseResult &result)
: _verbose{result["verbose"].as<bool>()}
{
    extractProcesses("process", result, _processes);
    extractProcesses("parent", result, _parentProcesses);
    decideIpVersion(result);
    setDisplayColumns(result);
}

void Engine::Config::extractProcesses(const std::string &optionName, const cxxopts::ParseResult &result, SelectedProcesses &selectedProcesses)
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

void Engine::Config::decideIpVersion(const cxxopts::ParseResult &result)
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

void Engine::Config::setDisplayColumns(const cxxopts::ParseResult &result)
{
    if(result.count("cols"))
    {
        const auto &colVec = result["cols"].as<std::vector<std::string>>();
        _displayColumns.insert(colVec.begin(), colVec.end());
    }
}
