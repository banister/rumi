#include "bpf_device.h"
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>

namespace
{
    const std::string bpfDeviceNamePrefix{"/dev/bpf"};
}

BpfDevice::BpfDevice(const std::string &interfaceName)
{
    auto config{findAndConfigureInterface(interfaceName)};
    _fd = std::move(config.fd);
    _bufferLength = config.bufferLength;
}

void BpfDevice::receive() const
{
    while(true)
    {
        std::vector<unsigned char> buf(_bufferLength);
        unsigned char *ptr = reinterpret_cast<unsigned char *>(buf.data());
        ssize_t length = read(_fd.get(), buf.data(), _bufferLength);

        while(ptr < buf.data() + length)
        {
            bpf_hdr *bh = reinterpret_cast<bpf_hdr *>(ptr);
            ether_header *eh = reinterpret_cast<ether_header *>(ptr + bh->bh_hdrlen);

            std::span<unsigned char> data(ptr + bh->bh_hdrlen, ptr + length);
            ptr += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
            if(ntohs(eh->ether_type) == ETHERTYPE_IP)
            {
                auto packet4 = Packet4::createFromData(data, sizeof(ether_header));
                if(!packet4)
                    continue;

                _packetReceivedFunc(PacketView{std::move(*packet4)});
            }
            else if(ntohs(eh->ether_type) == ETHERTYPE_IPV6)
            {
                auto packet6 = Packet6::createFromData(data, sizeof(ether_header));
                if(!packet6)
                    continue;

                _packetReceivedFunc(PacketView{std::move(*packet6)});
            }
        }
    }
}

BpfDevice::InterfaceConfig BpfDevice::findAndConfigureInterface(const std::string &interfaceName) const
{
    for(size_t interfaceNumber = 0; interfaceNumber < MaxBpfNumber; ++interfaceNumber)
    {
        const std::string bpfDeviceName{bpfDeviceNamePrefix + std::to_string(interfaceNumber)};

        Fd fd{open(bpfDeviceName.c_str(), O_RDWR)};
        // Could not open bpf device; increment bpf name and try again
        if(!fd) continue;

        // Complete list of bpf ioctls: https://www.freebsd.org/cgi/man.cgi?bpf(4)
        // Get buffer size
        std::uint32_t bufferLength{0};
        if(::ioctl(fd.get(), BIOCGBLEN, &bufferLength))
            throw SystemError("Could not get buffer size");

        // Set the interface we're inspecting
        ifreq interface{};
        ::strcpy(interface.ifr_name, interfaceName.c_str());
        if(::ioctl(fd.get(), BIOCSETIF, &interface))
            throw SystemError("Could not set interface");

        // Receive packets in real-time (unbuffered)
        std::uint32_t enable{1};
        if(::ioctl(fd.get(), BIOCIMMEDIATE, &enable))
            throw SystemError("Could not set immediate mode");

        // Forces the interface into promiscuous mode. All packets,
        // not just those destined for the local host, are processed.
        if(::ioctl(fd.get(), BIOCPROMISC, NULL))
            throw SystemError("Could not set promiscuous mode");

        return {std::move(fd), bufferLength};
    }

    throw SystemError("No available bpf devices. Tried up until " + std::to_string(MaxBpfNumber));
}


