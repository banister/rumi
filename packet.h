#pragma once

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "util.h"

// Both TCP and UDP are supported - this is the source/dest port part that's
// common to both headers.
struct TransportPortHeader
{
    std::uint16_t sport;
    std::uint16_t dport;
};

class Packet4
{
public:
    enum PacketType
    {
        Tcp,
        Udp,
        Other
    };

public:
    static std::optional<Packet4> createFromData(std::span<unsigned char> data,
                                             unsigned skipBytes);

public:
    Packet4(std::span<unsigned char> data, ip *pIpHdr, TransportPortHeader *pTransportHdr)
        : _data{data}, _ipHdr{pIpHdr}, _transportHdr{pTransportHdr}
    {
         // Prepar data for re-injection
        // ip_len and ip_off must be in host order (macOS quirk)
        _ipHdr->ip_len = ntohs(_ipHdr->ip_len);
        _ipHdr->ip_off = ntohs(_ipHdr->ip_off);
        _ipHdr->ip_sum = 0;
        _ipHdr->ip_sum = csum(reinterpret_cast<const std::uint16_t *>(_ipHdr), _ipHdr->ip_len);
     }

    // ip->ip_len
    std::uint16_t len() const { return _ipHdr->ip_len; }

    // ip->ip_p
    PacketType packetType() const;

    std::uint8_t protocol() const { return _ipHdr->ip_p; }

    // tcphdr->th_sport
    std::uint16_t sourcePort() const {return _transportHdr ? ntohs(_transportHdr->sport) : 0; }
    // tcphdr->th_dport
    std::uint16_t destPort() const {return _transportHdr ? ntohs(_transportHdr->dport) : 0; }

    std::uint32_t sourceAddress() const { return ntohl(_ipHdr->ip_src.s_addr); }
    std::uint32_t destAddress() const { return ntohl(_ipHdr->ip_dst.s_addr); }

    std::string toString() const;

    // Get the raw data for re-injection
    ip * toRaw() const { return _ipHdr; }

private:
    std::uint16_t csum(const std::uint16_t *buf, int words);

private:
    // Actual packet data buffer (_ipHdr and _transportHdr point to this)
    std::span<unsigned char> _data;
    ip * _ipHdr;
    TransportPortHeader * _transportHdr;
};

class Packet6
{
public:
    enum PacketType
    {
        Tcp,
        Udp,
        Other
    };

public:
    static std::optional<Packet6> createFromData(std::span<unsigned char> data,
                                              unsigned skipBytes);
public:
    Packet6(std::span<unsigned char> data, std::uint8_t transportProtocol,
           ip6_hdr *pIpHdr, TransportPortHeader *pTransportHdr)
        : _data{data}, _transportProtocol{transportProtocol},
          _ipHdr{pIpHdr}, _transportHdr{pTransportHdr}
    {
    }

    // _ipHdrr->ip6_nxt (next header)
    PacketType packetType() const;

    std::uint8_t protocol() const { return _transportProtocol; }

    // tcphdr->th_sport
    std::uint16_t sourcePort() const {return _transportHdr ? ntohs(_transportHdr->sport) : 0; }
    // tcphdr->th_dport
    std::uint16_t destPort() const {return _transportHdr ? ntohs(_transportHdr->dport) : 0; }

    const in6_addr& sourceAddress() const {return _ipHdr->ip6_src;}
    const in6_addr& destAddress() const {return _ipHdr->ip6_dst;}

    std::string toString() const;

    // Get the raw data for re-injection
    ip6_hdr * toRaw() const { return _ipHdr; }

private:
    // Actual packet data buffer (_ipHdr and _transportHdr point to this)
    std::span<unsigned char> _data;
    std::uint8_t _transportProtocol;
    ip6_hdr * _ipHdr;
    TransportPortHeader * _transportHdr;
};

class PacketView
{
public:
    PacketView(Packet4 packet4) : _packet{std::move(packet4)} {}
    PacketView(Packet6 packet6) : _packet{std::move(packet6)} {}

public:
    std::uint16_t sourcePort() const;
    std::uint16_t destPort() const;
    std::string sourceAddress() const;
    std::string destAddress() const;
    std::string toString() const;
    bool isIpv4() const;
    bool isIpv6() const;
    std::uint8_t transportProtocol() const;
    bool hasTransport() const {return transportProtocol() == IPPROTO_UDP || transportProtocol() == IPPROTO_TCP;}
    std::string transportName() const {return hasTransport() ? (transportProtocol() == IPPROTO_UDP ? "UDP" : "TCP") : "";}
    IPVersion ipVersion() const;

private:
    std::variant<Packet4, Packet6> _packet;
};
