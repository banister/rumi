#pragma once
#include "util.h"
#include <bsm/libbsm.h>
#include <bsm/audit.h>
#include <security/audit/audit_ioctl.h>
#include <bsm/audit_kevents.h>

class AuditPipe
{
public:
    struct ProcessEvent
    {
        enum Mode {Unknown, Starting, Exiting};
        Mode mode{Mode::Unknown};

        uint16_t type{};
        pid_t pid{};
        pid_t ppid{};
        uid_t uid{};
        uint32_t exitStatus{};
        std::string path;
        std::vector<std::string> arguments;
    };

private:
    using ProcCallbackT = std::function<void(const ProcessEvent&)>;

public:
    AuditPipe();

public:
    void onProcessStarted(ProcCallbackT proc) { _procStartedFunc = std::move(proc); }
    void onProcessExited(ProcCallbackT proc) { _procExitedFunc = std::move(proc); }
    void readLoop() const;

private:
    void processToken(const tokenstr_t &token, ProcessEvent &process, ProcessEvent &lastFork) const;

private:
    AutoCloseFile _auditFile;
    ProcCallbackT _procStartedFunc=[](auto&){};
    ProcCallbackT _procExitedFunc=[](auto&){};
};

