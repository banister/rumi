#pragma once

#include "common.h"
#include "fd.h"
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
         std::vector<std::byte> buf(_bufferLength);
         std::byte *ptr = reinterpret_cast<std::byte*>(buf.data());

         ssize_t length = read(_fd.get(), buf.data(), _bufferLength);

         while (ptr < buf.data() + length)
         {
             bpf_hdr *bh = reinterpret_cast<bpf_hdr*>(ptr);
             /* Start of ethernet frame */
             ether_header *eh = reinterpret_cast<ether_header*>(ptr + bh->bh_hdrlen);
             ptr += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);

             func(eh);
         }
    }

private:
    Fd _fd;
    std::uint32_t _bufferLength;
};
