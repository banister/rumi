#include "util.h"
#include "ip_address.h"
#include "packet.h"

std::optional<Packet4> Packet4::createFromData(std::span<unsigned char> data,
                                          unsigned skipBytes)
{
    // Must contain an IP header, we read these fields
    if(data.size() < skipBytes + sizeof(ip))
    {
        spacer{std::cerr} << "IPv4 Packet of length " << data.size()
            << " is too small; need" << (skipBytes + sizeof(ip))
            << " bytes for utun and IP headers";

        return {};
    }

    unsigned char *pPkt = data.data() + skipBytes;
    ip *pIpHdr{reinterpret_cast<ip*>(pPkt)};

    // The packet must contain enough data to cover the IP total length - we
    // use this to tell the network stack how much data to read when we
    // reinject.  Extra data shouldn't occur but would be ignored if it did
    unsigned ipTotalLen = ntohs(pIpHdr->ip_len);
    if(data.size() < skipBytes + ipTotalLen)
    {
        spacer{std::cerr} << "IPv4 Packet of length" << data.size()
            << "is too small; IP header indicates length of"
            << ipTotalLen;

        return {};
    }

    // If the packet is TCP or UDP, we also need the transport ports (part
    // of the transport header)
    TransportPortHeader *pTransportHdr{};
    if(pIpHdr->ip_p == IPPROTO_TCP || pIpHdr->ip_p == IPPROTO_UDP)
    {
        unsigned ipHdrLen = pIpHdr->ip_hl * 4;
        if(data.size() < skipBytes + ipHdrLen + sizeof(TransportPortHeader))
        {
            spacer{std::cerr} << "IPv4 Packet of length" << data.size()
                << "is too small; need"
                << (skipBytes + ipHdrLen + sizeof(TransportPortHeader))
                << "bytes for utun, IP, and transport headers";

            return {};
        }
        pTransportHdr = reinterpret_cast<TransportPortHeader *>(pPkt + ipHdrLen);
    }

    return Packet4{data, pIpHdr, pTransportHdr};
}

std::uint16_t Packet4::csum(const std::uint16_t *pData, int words)
{
    std::uint_fast32_t checksumTotal{};
    const std::uint16_t *pDataEnd = pData + (words);
    while(pData != pDataEnd)
    {
        checksumTotal += *pData;
        ++pData;
    }

    checksumTotal = (checksumTotal & 0x0000FFFF) + (checksumTotal >> 16);
    checksumTotal += (checksumTotal >> 16);
    return static_cast<std::uint16_t>(~checksumTotal);
}

std::string Packet4::toString() const
{
    const std::string sourceAddressStr = IPv4Address{ntohl(sourceAddress())}.toString();
    const std::string destAddressStr = IPv4Address{ntohl(destAddress())}.toString();
    char buf[50]{};

    if(packetType() != Other)
    {
        const std::string ptype = (packetType() == Udp ? "Udp" : packetType() == Tcp ? "Tcp" : "Other");
        snprintf(buf, sizeof(buf), "Packet %s: %s:%d -> %s:%d\n",
            ptype.c_str(), sourceAddressStr.c_str(), sourcePort(), destAddressStr.c_str(), destPort());

        return buf;
    }
    else
    {
        snprintf(buf, sizeof(buf), "Packet (protocol: %d): %s -> %s\n",
            protocol(), sourceAddressStr.c_str(), destAddressStr.c_str());
        return buf;
    }
}

Packet4::PacketType Packet4::packetType() const
{
    if(_ipHdr->ip_p == IPPROTO_TCP)
        return Tcp;
    else if(_ipHdr->ip_p == IPPROTO_UDP)
        return Udp;
    else
        return Other;
}

std::optional<Packet6> Packet6::createFromData(std::span<unsigned char> data,
                                            unsigned skipBytes)
{
    // Must contain an IPv6 header, we read these fields
    if(data.size() < skipBytes + sizeof(ip6_hdr))
    {
        spacer{std::cerr} << "IPv6 Packet of length" << data.size()
            << "is too small; need" << (skipBytes + sizeof(ip6_hdr))
            << "bytes for utun and IP headers";

        return {};
    }

    unsigned char *pPkt = data.data() + skipBytes;
    ip6_hdr *pIpHdr{reinterpret_cast<ip6_hdr*>(pPkt)};

    // The packet must contain enough data to cover the IP payload length - we
    // use this to tell the network stack how much data to read when we
    // reinject.  Extra data shouldn't occur but would be ignored if it did
    unsigned ipPayloadLen = ntohs(pIpHdr->ip6_ctlun.ip6_un1.ip6_un1_plen);
    if(data.size() < skipBytes + sizeof(ip6_hdr) + ipPayloadLen)
    {
        spacer{std::cerr} << "IPv6 Packet of length" << data.size()
            << "is too small; IP header indicates payload of"
            << ipPayloadLen;

        return {};
    }

    // Try to find a TCP/UDP transport header.
    std::uint8_t nextHeader = pIpHdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    unsigned transportHeaderOffset = skipBytes;
    unsigned nextHeaderOffset = sizeof(ip6_hdr);
    while(nextHeaderOffset)
    {
        transportHeaderOffset += nextHeaderOffset;
        nextHeaderOffset = 0;

        // Make sure there's still packet data left to read
        // The next header might not actually be an ip6_ext (it could be a
        // transport header, etc.) but it still needs to have at least 2 bytes.
        if(data.size() < transportHeaderOffset + sizeof(ip6_ext))
        {
            spacer{std::cerr} << "IPv6 Packet of length" << data.size()
                << "is too small; reached offset" << transportHeaderOffset
                << "looking for transport header";
            return {};
        }

        const ip6_ext *pExt = reinterpret_cast<const ip6_ext*>(data.data() + transportHeaderOffset);

        switch(nextHeader)
        {
            // These headers all have leading "next header" and "header length"
            // fields, and "header length" is in 8-byte units, not counting the
            // first 8 bytes.
            case 0: // hop by hop options
            case 43: // routing
            case 60: // destination options
            case 135: // mobility
            case 140: // shim6
            {
                nextHeader = pExt->ip6e_nxt;
                nextHeaderOffset = pExt->ip6e_len * 8 + 8;
                break;
            }
            // The authentication header uses 4-byte units, but also excludes
            // the first 8 bytes
            case 51: // authentication
            {
                nextHeader = pExt->ip6e_nxt;
                nextHeaderOffset = pExt->ip6e_len * 4 + 8;
                break;
            }
            // The fragment header can have a fixed size, but would require us
            // to inspect the fragment identification values and maintain a
            // cache to reinject the subsequent fragments to the correct
            // destination.  For now, fragmented packets are not supported.
            case 44: // fragment
            {
                std::cerr << "Dropping IPv6 fragmented packet; fragments not supported";
                break;
            }
            // Other header types can't have subsequent headers, like
            // 59 (no next header) or 139 (host identity protocol).
            default:
                break;
        }

        // If we found an offset, we'll continue to the next header, otherwise
        // we're done, check if the last header we found is a transport header
    }

    // If the packet is TCP or UDP, we also need the transport ports (part
    // of the transport header)
    TransportPortHeader *pTransportHdr{};
    if(nextHeader == IPPROTO_TCP || nextHeader == IPPROTO_UDP)
    {
        if(data.size() < transportHeaderOffset + sizeof(TransportPortHeader))
        {
            spacer{std::cerr} << "IPv6 Packet of length" << data.size()
                << "is too small; need"
                << (transportHeaderOffset + sizeof(TransportPortHeader))
                << "bytes for utun, IP, and transport headers";

            return {};
        }
        pTransportHdr = reinterpret_cast<TransportPortHeader *>(data.data() + transportHeaderOffset);
    }

    return Packet6{data, nextHeader, pIpHdr, pTransportHdr};
}

Packet6::PacketType Packet6::packetType() const
{
    if(_transportProtocol == IPPROTO_TCP)
        return Tcp;
    else if(_transportProtocol == IPPROTO_UDP)
        return Udp;
    else
        return Other;
}

std::string Packet6::toString() const
{
    const std::string sourceAddressStr = IPv6Address{sourceAddress()}.toString();
    const std::string destAddressStr = IPv6Address{destAddress()}.toString();
    char buf[100]{};

    if(packetType() != Other)
    {
        std::string ptype = (packetType() == Udp ? "Udp" : packetType() == Tcp ? "Tcp" : "Other");

        snprintf(buf, sizeof(buf), "Packet %s: %s.%d -> %s.%d\n",
            ptype.c_str(), sourceAddressStr.c_str(), sourcePort(), destAddressStr.c_str(), destPort());

        return buf;
    }
    else
    {
        snprintf(buf, sizeof(buf), "Packet (protocol: %d) %s -> %s\n",
            protocol(), sourceAddressStr.c_str(), destAddressStr.c_str());

        return buf;
    }
}
