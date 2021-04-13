#pragma once

#include "util.h"
#include "fd.h"
#include "packet.h"
#include <net/bpf.h>
#include <netinet/if_ether.h>

class BpfDevice
{
public:
     static std::optional<BpfDevice> create(const std::string &interfaceName);

 public:
     BpfDevice(Fd fd, std::uint32_t bufferLength)
     : _fd{std::move(fd)}
     , _bufferLength{bufferLength}
     {
     }

 public:
     template <typename Func_T>
     void onPacketReceived(Func_T func) const
     {
         std::vector<unsigned char> buf(_bufferLength);
         unsigned char *ptr = reinterpret_cast<unsigned char*>(buf.data());
         ssize_t length = read(_fd.get(), buf.data(), _bufferLength);

         while(ptr < buf.data() + length)
         {
             bpf_hdr *bh = reinterpret_cast<bpf_hdr*>(ptr);
             ether_header *eh = reinterpret_cast<ether_header*>(ptr + bh->bh_hdrlen);

             std::span<unsigned char> data(ptr + bh->bh_hdrlen, ptr + length);
             ptr += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
             if(ntohs(eh->ether_type) == ETHERTYPE_IP)
             {
                 auto packet4 = Packet4::createFromData(data, sizeof(ether_header));
                 if(!packet4)
                     continue;

                func(PacketView{std::move(*packet4)});
             }
             else if(ntohs(eh->ether_type) == ETHERTYPE_IPV6)
             {
                 auto packet6 = Packet6::createFromData(data, sizeof(ether_header));
                 if(!packet6)
                     continue;

                func(PacketView{std::move(*packet6)});
             }
         }
    }

private:
    Fd _fd;
    std::uint32_t _bufferLength;
};
