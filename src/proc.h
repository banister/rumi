#pragma once
#include "common.h"

namespace Proc
{
    pid_t getppid(pid_t pid);
    std::string pidToPath(pid_t pid);
}
