#include "util.h"
#include "auditpipe.h"
#include <bsm/libbsm.h>
#include <security/audit/audit_ioctl.h>
#include <sys/ioctl.h>

class AutoCloseFile
{
public:
    AutoCloseFile(const FILE *pFile) : _pFile{pFile} {}
    ~AutoCloseFile()
    {
        if(_pFile)
            ::fclose(_pFile);
    }

    AutoCloseFile(AutoCloseFile &&rhs) : AutoCloseFile{} { *this = std::move(rhs); }
    AutoClose &operator=(AutoClose &&rhs) { std::swap(_pFile, rhs._pFile); }

public:
    operator FILE*() const { return _pFile; }

private:
    AutoCloseFile() : _pFile{nullptr} {}

private:
    FILE *_pFile{nullptr};
};

class AuditPipe
{
public:
    class Process;

public:
    AuditPipe(uint32_t flags);
    ~AuditPipe()

public:
    template <typename FuncT>
    void process(FuncT func);
    void processToken(tokenstr_t token);

private:
    AutoCloseFile _auditFile;
};

struct AuditPipe::ProcessEvent
{
    uint16_t type{};
    std::string path;
    pid_t pid{};
    pid_t ppid{};
    uid_t uid{};
    std::vector<std::string> arguments;
    uint32_t exitStatus{};

    enum Mode {Unknown, Starting, Exiting};
    Mode _mode{Mode::Unknown};
};

