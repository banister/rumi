#pragma once

#include "common.h"
#include "config.h"

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
        std::cout << "pid: " << _event.pid << " ppid: " << _event.ppid << " - ";
        std::cout << (_config.verbose() ? _event.path : basename(_event.path)) << " ";

        for(size_t index=0; const auto &arg : _event.arguments)
        {
            // Skip argv[0] (program name) as we already display the path
            if(index != 0)
                std::cout << arg << " ";

            ++index;
        }

        std::cout << std::endl;
    }

private:
    std::string basename(const std::string& path) const
    {
        return static_cast<std::string>(fs::path(path).filename());
    }

private:
    T& _event;
    const Config &_config;
};

}
