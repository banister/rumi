#pragma once

#include <optional>
#include <vector>
#include <string>
#include <iostream>
#include <array>
#include <set>
#include <span>
#include <variant>
#include <compare>
#include <unistd.h>
#include <stdio.h>
#include <sys/errno.h>
#include <string.h>
#include <arpa/inet.h>

// Types
using PortSet = std::set<std::uint16_t>;
enum IPVersion { IPv4, IPv6 };
