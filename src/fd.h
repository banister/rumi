#pragma once
#include <algorithm>
#include <unistd.h>

class Fd
{
public:
    enum : int { Invalid = -1 };

public:
    Fd() : _fd{Invalid} {}
    Fd(int fd) :_fd{fd} {}
    ~Fd() {close();}

    Fd(Fd &&other) : _fd{std::exchange(other._fd, Invalid)} {}
    Fd& operator=(Fd &&other);

public:
    void close();
    explicit operator bool() {return _fd != Invalid;}
    int get() const {return _fd;}

private:
    int _fd;
};
