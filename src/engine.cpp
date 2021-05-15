#include "engine.h"
#include "packet.h"
#include <fmt/core.h>
#include "vendor/cxxopts.h"

void Engine::start(int argc, char **argv)
{
    cxxopts::Options options{"Columbo", "Per-app traffic analyzer"};

    options.allow_unrecognised_options();
    options.add_options()
        ("h,help", "Display this help message.")
        ("i,interface", "The interfaces to listen on.", cxxopts::value<std::vector<std::string>>())
        ("a,analyze", "Analyze traffic.",cxxopts::value<bool>()->default_value("true"))
        ("s,sockets", "Show socket information.")
        ("v,verbose", "Verbose output.",cxxopts::value<bool>()->default_value("false"));

    auto result = options.parse(argc, argv);

    const auto &unmatched = result.unmatched();
    const std::vector<std::string> appNames{unmatched.begin(), unmatched.end()};

    // Setup config options
    _config.verbose = result["verbose"].as<bool>();

    if(result.count("help"))
    {
        std::cout << options.help();
        return;
    }

    if(result.count("sockets"))
    {
        showConnections(appNames, IPVersion::Both);
        return;
    }

    if(result["analyze"].as<bool>())
    {
        showTraffic(appNames, IPVersion::Both);
        return;
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
