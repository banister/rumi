#pragma once

#include "common.h"

template <typename Derived>
class Traceable
{
public:
    friend std::ostream& operator<<(std::ostream &stream, const Traceable &traceable)
    {
        stream << static_cast<const Derived&>(traceable).toString() << "\n";
        return stream;
    }
};

class ErrorTracer : public Traceable<ErrorTracer>
{
public:
    ErrorTracer(int code) : _code{code} {}

public:
    std::string toString() const;

private:
    int _code;
};

// Use like: spacer{cerr} << "foo" << "bar";
// #=> "foo bar"
class spacer
{
    std::ostream &o;
    bool writeSpace = false;
public:
    explicit spacer(std::ostream &o) : o(o) {}

    template <typename T>
    friend spacer operator<<(spacer &&s, T &&t)
    {
        if(s.writeSpace)
            s.o << ' ';
        else
            s.writeSpace = true;
        s.o << std::forward<T>(t);
        return s;
    }
};
