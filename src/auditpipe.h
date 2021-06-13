#pragma once
#include "util.h"
#include <bsm/libbsm.h>
#include <bsm/audit.h>
#include <security/audit/audit_ioctl.h>
#include <bsm/audit_kevents.h>

class AuditPipe
{
public:
    class Error;

public:
    struct ProcessEvent
    {
        uint16_t type{};
        std::string path;
        pid_t pid{};
        pid_t ppid{};
        uid_t uid{};
        std::vector<std::string> arguments;
        uint32_t exitStatus{};

        enum Mode {Unknown, Starting, Exiting};
        Mode mode{Mode::Unknown};
    };

public:
    AuditPipe();

public:
    template <typename FuncA, typename FuncB>
    void process(FuncA processStartFunc, FuncB processExitFunc)
    {
        std::optional<ProcessEvent> pProcess;
        std::optional<ProcessEvent> pLastFork;

        while(1)
        {
            //read a single audit record
            // note: buffer is allocated by function, so must be freed when done
            uint8_t *recordBuffer{nullptr};
            auto recordLength = au_read_rec(_auditFile, &recordBuffer);

            if(recordLength == -1)
                continue;

            auto cleanup = scopeGuard([&recordBuffer] { if(recordBuffer) ::free(recordBuffer); });

            auto recordBalance{recordLength};
            auto processedLength{0};

            pProcess.emplace();
            pLastFork.emplace();

            while(recordBalance != 0)
            {
                tokenstr_t token{};
                auto ret = au_fetch_tok(&token, recordBuffer + processedLength, recordBalance);

                if(ret == -1)
                    break;

                processToken(token, *pProcess, *pLastFork);

                if(pProcess->mode == ProcessEvent::Starting)
                    processStartFunc(*pProcess);
                else if(pProcess->mode == ProcessEvent::Exiting)
                    processExitFunc(*pProcess);

                // add length of current token
                processedLength += token.len;
                //subtract length of current token
                recordBalance -= token.len;
            }
        }
    }

private:
    void processToken(const tokenstr_t &token, ProcessEvent &process, ProcessEvent &lastFork);

private:
    AutoCloseFile _auditFile;
};

