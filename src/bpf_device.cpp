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


