#pragma once

#include "util.h"
#include "fd.h"
#include "packet.h"
#include <net/bpf.h>
#include <netinet/if_ether.h>

class BpfDevice
{
    enum : size_t { MaxBpfNumber = 99 };

    using PktCallbackT = std::function<void(const PacketView&)>;

   struct InterfaceConfig
   {
       Fd fd;
       std::uint32_t bufferLength{0};
    };

public:
     BpfDevice(const std::string &interfaceName);

private:
    InterfaceConfig findAndConfigureInterface(const std::string &interfaceName) const;

public:
     void onPacketReceived(PktCallbackT proc) { _packetReceivedFunc = std::move(proc); }
     void receive() const;

private:
    Fd _fd;
    std::uint32_t _bufferLength;
    PktCallbackT _packetReceivedFunc=[](auto&){};
};
