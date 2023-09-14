#pragma once

#include "common.h"
#include "config.h"
#include "proc.h"

namespace View
{
namespace fs = std::filesystem;

template <typename T>
class Exec
{
public:
    Exec(const T& event, const Config& config)
    : _event{event}
    , _config{config}
    {}

public:
    void render() const
    {
        if(!_config.displayColumns().empty())
        {
            for(const auto &column : _config.displayColumns())
            {
                if(column == "pid")
                    std::cout << _event.pid << " ";
                else if(column == "ppid")
                    std::cout << _event.ppid << " ";
                else if(column == "path")
                    std::cout << _event.path << " ";
                else if(column == "ppath")
                    std::cout << Proc::pidToPath(_event.ppid) << " ";
                else if(column == "name")
                    std::cout << basename(_event.path) << " ";
                else if(column == "pname")
                    std::cout << basename(Proc::pidToPath(_event.ppid)) << " ";
                else if(column == "args")
                {
                    for(size_t index = 0; const auto &arg : _event.arguments)
                    {
                        // Skip argv[0] (program name) as we already display the path
                        if(index != 0)
                            std::cout << arg << " ";
                        ++index;
                    }
                }
            }
            std::cout << std::endl;
        }
        else
        {
            std::cout << "pid: " << _event.pid << " ppid: " << _event.ppid << " - ";
            std::cout << (_config.verbose() ? _event.path : basename(_event.path)) << " ";

            for (size_t index = 0; const auto &arg : _event.arguments)
            {
                // Skip argv[0] (program name) as we already display the path
                if (index != 0)
                    std::cout << arg << " ";

                ++index;
            }

            std::cout << std::endl;
        }
    }

private:
    std::string basename(const std::string& path) const
    {
        return static_cast<std::string>(fs::path(path).filename());
    }

    std::string join(const std::vector<std::string> &vec) const
    {
        std::stringstream str;
        for(size_t index = 0; const auto &arg : _event.arguments)
        {
            // Skip argv[0] (program name) as we already display the path
            if(index != 0)
                str << arg;

            if(index != 0 && index < (_event.arguments.size() - 1))
                str << " ";
            ++index;
        }
        return str.str();
    }

private:
    T& _event;
    const Config &_config;
};

}
