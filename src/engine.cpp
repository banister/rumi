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
        ("f,format", "Set format string.", cxxopts::value<std::string>())
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
    constexpr const char *ipv6FormatString = "{:.20} {} {}.{} > {}.{}\n";
    constexpr const char *ipv4FormatString = "{:.20} {} {}:{} > {}:{}\n";

    if(packet.isIpv6())
    {
        fmt::print(ipv6FormatString, appPath, packet.transportName(), packet.sourceAddress(), packet.sourcePort(),
                packet.destAddress(), packet.destPort());
    } 
    else 
    {
        fmt::print(ipv4FormatString, appPath, packet.transportName(), packet.sourceAddress(), packet.sourcePort(),
                packet.destAddress(), packet.destPort());
    }

    ::fflush(stdout);
}

