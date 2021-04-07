#include "fd.h"
#include <unistd.h>

Fd::~Fd()
{
    if(*this)
        ::close(_fd);
}





