#include "auditpipe.h"
#include <sys/ioctl.h>
#include <libproc.h>
#include <sys/types.h>
#include <sys/sysctl.h>

namespace
{
    const char* auditPipeLocation{"/dev/auditpipe"};

    uint32_t selectionFlags =
        // 0x00000000 | // Invalid Class (no)
        // 0x00000001 | // File read (fr)
        // 0x00000002 | // File write (fw)
        // 0x00000004 | // File attribute access (fa)
        // 0x00000008 | // File attribute modify (fm)
        // 0x00000010 | // File create (fc)
        // 0x00000020 | // File delete (fd)
        // 0x00000040 | // File close (cl)
        0x00000080 | // Process (pc)
        // 0x00000100 | // Network (nt)
        // 0x00000200 | // IPC (ip)
        // 0x00000400 | // Non attributable (na)
        // 0x00000800 | // Administrative (ad)
        // 0x00001000 | // Login/Logout (lo)
        // 0x00002000 | // Authentication and authorization (aa)
        // 0x00004000 | // Application (ap)
        // 0x20000000 | // ioctl (io)
        0x40000000; // | // exec (ex)
        // 0x80000000 | // Miscellaneous (ot)
        // 0xffffffff ; // All flags set (all)

    pid_t getppid(pid_t pid)
    {
        pid_t ppid{-1};
        kinfo_proc proc{};
        size_t procBufferSize{sizeof(kinfo_proc)};
        const uint32_t mibLength{4};

        //init mib
        int mib[mibLength] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
        auto ret = sysctl(mib, mibLength, &proc, &procBufferSize, nullptr, 0);

        //check if got ppid
        if(ret == 0 && procBufferSize != 0)
            ppid = proc.kp_eproc.e_ppid;

        return ppid;
    }

    std::string pidToPath(pid_t pid)
    {
        std::string path;
        path.resize(PROC_PIDPATHINFO_MAXSIZE);
        proc_pidpath(pid, &path[0], path.size());
        return path;
    }
}

AuditPipe::AuditPipe()
{
    auto auditFile = AutoCloseFile{::fopen(auditPipeLocation, "r")};
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
        std::cerr << "Could not flush pipe " << ErrorTracer{errno};

    _auditFile = std::move(auditFile);
}

void AuditPipe::readLoop() const
{
    std::optional<ProcessEvent> pProcess;
    std::optional<ProcessEvent> pLastFork;

    while (true)
    {
        //read a single audit record
        // note: buffer is allocated by function, so must be freed when done
        uint8_t *recordBuffer{nullptr};
        auto recordLength = au_read_rec(_auditFile, &recordBuffer);

        if (recordLength == -1)
            continue;

        auto cleanup = scopeGuard([&recordBuffer] { if (recordBuffer) ::free(recordBuffer); });

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

            if(pProcess->mode == ProcessEvent::Starting && !pProcess->arguments.empty())
            {
                _procStartedFunc(*pProcess);
            }
            else if(pProcess->mode == ProcessEvent::Exiting && !pProcess->arguments.empty())
            {
                _procExitedFunc(*pProcess);
            }

            // add length of current token
            processedLength += token.len;
            //subtract length of current token
            recordBalance -= token.len;
        }
    }
}

void AuditPipe::processToken(const tokenstr_t &token, ProcessEvent &process, ProcessEvent &lastFork) const
{
    auto shouldProcessRecord = [](uint16_t eventType)
    {
        if(eventType == AUE_EXEC || eventType == AUE_EXIT || eventType == AUE_FORK || eventType == AUE_EXECVE || eventType == AUE_POSIX_SPAWN)
            return true;

        return false;
    };

    switch(token.id)
    {
    //handle start of record
    // grab event type, which allows us to ignore events not of interest
    case AUT_HEADER32:
    case AUT_HEADER32_EX:
    case AUT_HEADER64:
    case AUT_HEADER64_EX:
    {
        //save type
        process.type = token.tt.hdr32.e_type;

        break;
    }

    //path
    // note: this might be updated/replaced later (if it's '/dev/null', etc)
    case AUT_PATH:
    {
        //save path
        process.path = token.tt.path.path;

        break;
    }

    //subject
    //  extract/save pid || ppid
    //  all these cases can be treated as subj32 cuz only accessing initial members
    case AUT_SUBJECT32:
    case AUT_SUBJECT32_EX:
    case AUT_SUBJECT64:
    case AUT_SUBJECT64_EX:
    {
        //SPAWN (pid/ppid)
        // if there was an AUT_ARG32 (which always come first), that's the pid! so this will be the ppid
        if(AUE_POSIX_SPAWN == process.type)
        {
            //no AUT_ARG32?
            // set as pid, and try manually to get ppid
            if(process.pid == 0)
            {
                //set pid
                process.pid = token.tt.subj32.pid;
                //manually get parent
                process.ppid = getppid(process.pid);
            }
            //pid already set (via AUT_ARG32)
            // this then, is the ppid
            else
            {
                //set ppid
                process.ppid = token.tt.subj32.pid;
            }
        }

        //FORK
        // ppid (pid is in AUT_ARG32)
        else if(AUE_FORK == process.type)
            //set ppid
            process.ppid = token.tt.subj32.pid;

        //AUE_EXEC/VE & AUE_EXIT
        // this is the pid
        else
        {
            //save pid
            process.pid = token.tt.subj32.pid;
            //manually get parent
            process.ppid = getppid(process.pid);
        }

        //get effective user id
        process.uid = token.tt.subj32.euid;

        break;
    }

    //args
    // SPAWN/FORK this is pid
    case AUT_ARG32:
    case AUT_ARG64:
    {
        //save pid
        if((AUE_POSIX_SPAWN == process.type) ||
            (AUE_FORK == process.type))
        {
            //32bit
            if(AUT_ARG32 == token.id)
            {
                //save
                process.pid = token.tt.arg32.val;
            }
            //64bit
            else
            {
                //save
                process.pid = static_cast<pid_t>(token.tt.arg64.val);
            }
        }

        //FORK
        // doesn't have token for path, so try manually find it now
        if(AUE_FORK == process.type)
        {
            //set path
            process.path.resize(PROC_PIDPATHINFO_MAXSIZE);
            proc_pidpath(process.pid, process.path.data(), process.path.size());
        }

        break;
    }

    //exec args
    // just save into args
    case AUT_EXEC_ARGS:
    {
        //save args
        auto argCount{token.tt.execarg.count};
        process.arguments.reserve(argCount);

        for(size_t i = 0; i < argCount; ++i)
        {
            const char* argument = token.tt.execarg.text[i];
            if(argument == nullptr)
                continue;

            //add argument
            process.arguments.emplace_back(argument);
        }

        break;
    }

    //exit
    // save status
    case AUT_EXIT:
    {
        //save
        process.exitStatus = token.tt.exit.status;

        break;
    }

    //record trailer
    // end/save, etc
    case AUT_TRAILER:
    {
        if(shouldProcessRecord(process.type))
        {
            //handle process exits
            if(AUE_EXIT == process.type)
                process.mode = ProcessEvent::Exiting;

            //handle process starts
            else
            {
                //also try get process path
                // this is the most 'trusted way' (since exec_args can change)
                process.path = pidToPath(process.pid);

                //failed to get path at runtime
                // if 'AUT_PATH' was something like '/dev/null' or '/dev/console' use arg[0]...yes this can be spoofed :/
                if(process.path.empty() || (process.path.starts_with("/dev/") && !process.arguments.empty()))
                    process.path = process.arguments[0];

                //save fork events
                // this will have ppid that can be used for child events (exec/spawn, etc)
                if(AUE_FORK == process.type)
                    lastFork = process;

                //when we don't have a ppid
                // see if there was a 'matching' fork() that has it (only for non AUE_FORK events)
                else if(process.ppid && lastFork.pid == process.pid)
                    process.ppid = lastFork.ppid;

                //handle new process
                process.mode = ProcessEvent::Starting;
            }
        }
        break;
    }

    default:;

    } //process token
}
