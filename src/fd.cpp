#include "fd.h"
#include <unistd.h>

Fd& Fd::operator=(Fd &&other)
{
    close();
    _fd = std::exchange(other._fd, Invalid);
    return *this;
}

void Fd::close()
{
    if(*this)
        ::close(_fd);

    _fd = Invalid;
}
