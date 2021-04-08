#pragma once
#include <algorithm>
class Fd
{
    enum : int { Invalid = -1 };

public:
    Fd() : _fd{Invalid} {}
    Fd(int fd) :_fd{fd} {}

    Fd(Fd &&other) : Fd{} {*this = std::move(other);}
    Fd& operator=(Fd &&other) { std::swap(_fd, other._fd); return *this; }

public:
    explicit operator bool() {return _fd != Invalid;}
    int get() const {return _fd;}
    ~Fd();

private:
    int _fd;
};
