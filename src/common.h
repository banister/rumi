#pragma once

#include <stdexcept>
#include <optional>
#include <vector>
#include <string>
#include <exception>
#include <iostream>
#include <memory>
#include <array>
#include <set>
#include <span>
#include <fmt/core.h>
#include <variant>
#include <compare>
#include <functional>
#include <unistd.h>
#include <stdio.h>
#include <sys/errno.h>
#include <string.h>
#include <span>
#include <arpa/inet.h>

#if defined(__linux__)
#define CMB_LINUX
#elif defined(__APPLE__)
#define CMB_MACOS
#define CMB_MAC
#else
#define CMB_WIN
#define CMB_WINDOWS
#endif

// Types
using PortSet = std::set<std::uint16_t>;
enum IPVersion { IPv4, IPv6, Both };

inline std::string ipVersionToString(IPVersion ipVersion)
{
    if(ipVersion == IPv4)
        return "IPv4";
    else if(ipVersion == IPv6)
        return "IPv6";
    else
        return "IPv4/IPv6";
}
