#include "auditpipe.h"
#include <sys/ioctl.h>
#include <libproc.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include "proc.h"

namespace
{
    const char auditPipeLocation[]{"/dev/auditpipe"};

    // See /etc/security/audit_class for the full list
    // We're only interested in process and exec audit events.
    uint32_t selectionFlags = 0x00000080 | // process (pc)
                              0x40000000;  // exec (ex)
}

AuditPipe::AuditPipe()
{
    AutoCloseFile auditFile{::fopen(auditPipeLocation, "r")};
    if(auditFile == nullptr)
        throw SystemError("Could not construct audit pipe");

    // Grab the fd for use with ioctl
    auto fd{::fileno(auditFile)};

    int mode{AUDITPIPE_PRESELECT_MODE_LOCAL};
    if(::ioctl(fd, AUDITPIPE_SET_PRESELECT_MODE, &mode) == -1)
        throw SystemError("Could not set preselect mode to local");

    int queueLength{0};
    if(::ioctl(fd, AUDITPIPE_GET_QLIMIT_MAX, &queueLength) == -1)
        throw SystemError("Could not get max queue length");

    if(::ioctl(fd, AUDITPIPE_SET_QLIMIT, &queueLength) == -1)
        throw SystemError("Could not set  queue length");

    if(::ioctl(fd, AUDITPIPE_SET_PRESELECT_FLAGS, &selectionFlags) == -1)
        throw SystemError("Could not set preselection flags");

    if(::ioctl(fd, AUDITPIPE_SET_PRESELECT_NAFLAGS, &selectionFlags) == -1)
        throw SystemError("Could not set preselection NA flags");

    if(::ioctl(fd, AUDITPIPE_FLUSH) == -1)
        std::cerr << "Could not flush pipe " << ErrorTracer{};  // Non critical error

    _auditFile = std::move(auditFile);
}

void AuditPipe::receive() const
{
    std::optional<ProcessEvent> pProcessEvent;
    std::optional<ProcessEvent> pLastForkEvent;

    while(true)
    {
        uint8_t *recordBuffer{nullptr};
        // Buffer is allocated on the heap - we ensure it's freed later with a scope guard
        auto recordLength = au_read_rec(_auditFile, &recordBuffer);

        if(recordLength == -1)
            continue;

        // Cleanup allocated buffer
        auto cleanup = scopeGuard([&recordBuffer] { if(recordBuffer) ::free(recordBuffer); });

        auto recordBalance{recordLength};
        auto processedLength{0};

        pProcessEvent.emplace();
        pLastForkEvent.emplace();

        while(recordBalance != 0)
        {
            tokenstr_t token{};
            auto ret = au_fetch_tok(&token, recordBuffer + processedLength, recordBalance);

            if(ret == -1)
                break;

            processToken(token, *pProcessEvent, *pLastForkEvent);

            if(!pProcessEvent->arguments.empty())
            {
                if(pProcessEvent->mode == ProcessEvent::Starting)
                    _procStartedFunc(*pProcessEvent);
                else if(pProcessEvent->mode == ProcessEvent::Exiting)
                    _procExitedFunc(*pProcessEvent);
            }

            processedLength += token.len;
            recordBalance -= token.len;
        }
    }
}

void AuditPipe::processToken(const tokenstr_t &token, ProcessEvent &processEvent, ProcessEvent &lastForkEvent) const
{
    auto shouldProcessRecord = [](uint16_t eventType)
    {
        if(eventType == AUE_EXEC || eventType == AUE_EXIT || eventType == AUE_FORK || eventType == AUE_EXECVE || eventType == AUE_POSIX_SPAWN)
            return true;

        return false;
    };

    switch(token.id)
    {
    // Determine process type from header
    case AUT_HEADER32:
    case AUT_HEADER32_EX:
    case AUT_HEADER64:
    case AUT_HEADER64_EX:
    {
        processEvent.type = token.tt.hdr32.e_type;
        break;
    }

    // Save the path of the process
    case AUT_PATH:
    {
        processEvent.path = token.tt.path.path;
        break;
    }

    // Get pid and ppid
    case AUT_SUBJECT32:
    case AUT_SUBJECT32_EX:
    case AUT_SUBJECT64:
    case AUT_SUBJECT64_EX:
    {
        if(AUE_POSIX_SPAWN == processEvent.type)
        {
            if(processEvent.pid == 0)
            {
                processEvent.pid = token.tt.subj32.pid;
                processEvent.ppid = Proc::getppid(processEvent.pid);
            }
            else
            {
                processEvent.ppid = token.tt.subj32.pid;
            }
        }
        else if(AUE_FORK == processEvent.type)
        {
            processEvent.ppid = token.tt.subj32.pid;
        }
        else
        {
            processEvent.pid = token.tt.subj32.pid;
            processEvent.ppid = Proc::getppid(processEvent.pid);
        }

        processEvent.uid = token.tt.subj32.euid;
        break;
    }

    // Get pid
    case AUT_ARG32:
    case AUT_ARG64:
    {
        if(AUE_POSIX_SPAWN == processEvent.type || AUE_FORK == processEvent.type)
        {
            if(AUT_ARG32 == token.id)
                processEvent.pid = token.tt.arg32.val;
            else
                processEvent.pid = static_cast<pid_t>(token.tt.arg64.val);
        }

        if(AUE_FORK == processEvent.type)
            processEvent.path = Proc::pidToPath(processEvent.pid);

        break;
    }

    // Store args
    case AUT_EXEC_ARGS:
    {
        auto argCount{token.tt.execarg.count};
        processEvent.arguments.reserve(argCount);

        for(size_t i = 0; i < argCount; ++i)
        {
            const char* argument = token.tt.execarg.text[i];
            if(argument == nullptr)
                continue;

            processEvent.arguments.emplace_back(argument);
        }
        break;
    }

    // Exit status
    case AUT_EXIT:
    {
        processEvent.exitStatus = token.tt.exit.status;
        break;
    }

    // Trailer (parsing is complete)
    case AUT_TRAILER:
    {
        if(shouldProcessRecord(processEvent.type))
        {
            if(AUE_EXIT == processEvent.type)
            {
                processEvent.mode = ProcessEvent::Exiting;
            }
            else
            {
                processEvent.path = Proc::pidToPath(processEvent.pid);

                if(((processEvent.path.empty()  || processEvent.path.starts_with("/dev/")) && !processEvent.arguments.empty()))
                    processEvent.path = processEvent.arguments.at(0);

                if(AUE_FORK == processEvent.type)
                    lastForkEvent = processEvent;

                else if(processEvent.ppid && lastForkEvent.pid == processEvent.pid)
                    processEvent.ppid = lastForkEvent.ppid;

                processEvent.mode = ProcessEvent::Starting;
            }
        }
        break;
    }
    default: // No-op
    ;
    }
}
