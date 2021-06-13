#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <iostream>
#include <fmt/core.h>
#include "engine.h"
#include "mac_engine.h"

int main(int argc, char** argv)
{

    std::unique_ptr<Engine> engine;

#if defined(CMB_MACOS)
    engine = std::make_unique<MacEngine>();
#endif

    try
    {
        engine->start(argc, argv);
    }
    catch(const std::exception &ex)
    {
        std::cerr << "Error: " << ex.what() << std::endl;
    }

    return 0;
}
