#include "ip_address.h"

IPv4Address::IPv4Address(const std::string &addressString)
{
    std::uint32_t networkAddress{};
    if (inet_pton(AF_INET, addressString.c_str(), &networkAddress) == 1)
        // We store in host byte order
        _address = ntohl(networkAddress);
}

std::string IPv4Address::toString() const
{
    char buf[INET_ADDRSTRLEN]{};
    std::uint32_t networkOrder{htonl(_address)};
    if(inet_ntop(AF_INET, &networkOrder, buf, sizeof(buf)))
        return buf;
    else
        return {};
}

IPv6Address::IPv6Address(const std::string &addressString)
{
    inet_pton(AF_INET6, addressString.c_str(), _address);
}

IPv6Address::IPv6Address(const AddressType &address)
{
    std::copy(std::begin(address), std::end(address), std::begin(_address));
}

IPv6Address::IPv6Address(const std::uint8_t *pAddress)
{
    std::copy(pAddress, pAddress + sizeof(AddressType), std::begin(_address));
}

IPv6Address::IPv6Address(const in6_addr &address) : IPv6Address(reinterpret_cast<const std::uint8_t*>(&address))
{
}

std::string IPv6Address::toString() const
{
    char buf[INET6_ADDRSTRLEN]{};
    if(inet_ntop(AF_INET6, _address, buf, sizeof(buf)))
        return buf;
    else
        return {};
}
