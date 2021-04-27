#pragma once
#include "util.h"

class IPv4Address
{
public:
    IPv4Address() : _address{} {}
    // Expects an address in host byte order
    IPv4Address(std::uint32_t address) : _address{address} {}
    IPv4Address(const std::string &addressString);
    auto operator<=>(const IPv4Address&) const = default;

public:
    bool isNull() const {return _address != 0;}
    std::uint32_t address() const {return _address;}
    std::string toString() const;

private:
    std::uint32_t _address;
};

class IPv6Address
{
    using AddressType = std::uint8_t[16];
public:
    IPv6Address() : _address{} {}
    IPv6Address(const std::string &addressString);
    IPv6Address(const std::uint8_t* pAddress);
    IPv6Address(const in6_addr &address);
    auto operator<=>(const IPv6Address&) const = default;

public:
    bool isNull() const {return std::all_of(std::begin(_address), std::end(_address), [](auto i) {return i == 0;});}
    std::string toString() const;

private:
    AddressType _address;
};
