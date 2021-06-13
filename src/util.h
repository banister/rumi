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

class AutoCloseFile
{
public:
    AutoCloseFile() : _pFile{nullptr} {};
    AutoCloseFile(FILE *pFile) : _pFile{pFile} {}
    ~AutoCloseFile() { close();  }

    AutoCloseFile(AutoCloseFile &&rhs) : _pFile{std::exchange(rhs._pFile, nullptr)} {}
    AutoCloseFile &operator=(AutoCloseFile &&rhs) { close(); _pFile = std::exchange(rhs._pFile, nullptr); return *this; }

public:
    void close()
    {
        if(_pFile)
        {
            ::fclose(_pFile);
            _pFile = nullptr;
        }
    }

public:
    operator FILE*() const { return _pFile; }

private:
    FILE *_pFile{nullptr};
};

template <typename FuncT>
class ScopeGuard
{
public:
    ScopeGuard(FuncT func) :_func{func} {}
    ~ScopeGuard() {_func();}

private:
    FuncT _func;
};

template <typename FuncT>
ScopeGuard<FuncT> scopeGuard(FuncT func)
{
    return ScopeGuard<FuncT>(func);
}
