#include "util.h"

std::string ErrorTracer::toString() const
{
    std::string message{strerror(_code)};
    return std::string{"(code: " + std::to_string(_code) + ") " + message};
}
