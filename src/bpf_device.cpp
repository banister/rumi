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

        const auto errorCondition = []() -> std::optional<BpfDevice>
        {
            std::cerr << ErrorTracer{errno};
            return {};
        };

        Fd fd{::open(bpfDeviceName.c_str(), O_RDWR)};
        // Could not open bpf device; increment bpf name and try again
        if(!fd) continue;

        // Complete list of bpf ioctls: https://www.freebsd.org/cgi/man.cgi?bpf(4)

        // Get buffer size
        std::uint32_t bufferLength{0};
        if(::ioctl(fd.get(), BIOCGBLEN, &bufferLength)) return errorCondition();

        // Set the interface we're inspecting
        ifreq interface{};
        ::strcpy(interface.ifr_name, interfaceName.c_str());
        if(::ioctl(fd.get(), BIOCSETIF, &interface)) return errorCondition();

        // Receive packets in real-time (unbuffered)
        std::uint32_t enable{1};
        if(::ioctl(fd.get(), BIOCIMMEDIATE, &enable)) return errorCondition();

        // Forces the interface into promiscuous mode. All packets,
        // not just those destined for the local host, are processed.
        if(::ioctl(fd.get(), BIOCPROMISC, NULL)) return errorCondition();

        return BpfDevice{std::move(fd), bufferLength};
    }

    std::cerr << "No available bpf devices. Tried up until " + std::to_string(MaxBpfNumber);

    return {};
}
