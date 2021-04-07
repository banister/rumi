#include "bpf_device.h"
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>

std::optional<BpfDevice> BpfDevice::create(const std::string &interfaceName)
{
    const std::string bpfDeviceNamePrefix{"/dev/bpf"};

    enum : int { MaxBpfNumber = 99 };
    for(int i = 0; i < MaxBpfNumber; ++i) {
        const std::string bpfDeviceName{bpfDeviceNamePrefix + std::to_string(i)};
        Fd fd{::open(bpfDeviceName.c_str(), O_RDWR)};
        if(fd)
        {
            std::uint32_t bufferLength{0};
            if(::ioctl(fd.get(), BIOCGBLEN, &bufferLength)) return {};

            // Set the interface we're inspecting
            ifreq interface{};
            ::strcpy(interface.ifr_name, interfaceName.c_str());
            if(::ioctl(fd.get(), BIOCSETIF, &interface)) return {};

            std::uint32_t enable{1};
            if(::ioctl(fd.get(), BIOCIMMEDIATE, &enable)) return {};

            if(::ioctl(fd.get(), BIOCPROMISC, NULL)) return {};

            return BpfDevice{std::move(fd), bufferLength};
        }
    }
    return {};
}

