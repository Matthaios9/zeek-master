

#include "zeek/input/readers/raw/Raw.h"

#include <fcntl.h>
#ifndef _MSC_VER
#include <spawn.h>
#endif
#ifdef _MSC_VER
#include <io.h>
#include <windows.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstdlib>

extern char** environ;

#include "zeek/WinHandle.h"
#include "zeek/input/Component.h"
#include "zeek/input/InputFile.h"
#include "zeek/input/readers/raw/Plugin.h"
#include "zeek/input/readers/raw/raw.bif.h"
#include "zeek/threading/SerialTypes.h"

extern "C" {
#include "zeek/3rdparty/setsignal.h"
}

using zeek::threading::Field;
using zeek::threading::Value;

#ifdef _MSC_VER
using UniqueHandle = zeek::detail::UniqueWinHandle;
#endif

namespace zeek::input::reader::detail {

const int Raw::block_size = 4096;

Raw::Raw(ReaderFrontend* frontend) : ReaderBackend(frontend), file(nullptr, fclose), stderrfile(nullptr, fclose) {
    execute = false;
    firstrun = true;
    mtime = 0;
    ino = 0;
    dev = 0;
    fsize = 0;
    forcekill = false;
    offset = 0;
    separator.assign(reinterpret_cast<const char*>(BifConst::InputRaw::record_separator->Bytes()),
                     BifConst::InputRaw::record_separator->Len());

    sep_length = BifConst::InputRaw::record_separator->Len();

    bufpos = 0;
    bufsize = 0;

    stdin_fileno = fileno(stdin);
    stdout_fileno = fileno(stdout);
    stderr_fileno = fileno(stderr);

    childpid = -1;

#ifdef _MSC_VER
    child_process_handle_ = INVALID_HANDLE_VALUE;
    child_job_handle_ = INVALID_HANDLE_VALUE;
#endif

    stdin_towrite = 0;
    use_stderr = false;
}

Raw::~Raw() { DoClose(); }

void Raw::DoClose() {
    if ( file )
        CloseInput();

    if ( execute && childpid > 0 ) {
#ifdef _MSC_VER
        HANDLE h = static_cast<HANDLE>(child_process_handle_);
        HANDLE job = static_cast<HANDLE>(child_job_handle_);


        if ( job != INVALID_HANDLE_VALUE ) {
            TerminateJobObject(job, 1);
            CloseHandle(job);
            child_job_handle_ = INVALID_HANDLE_VALUE;
        }
        else if ( h != INVALID_HANDLE_VALUE ) {
            TerminateProcess(h, 1);
        }

        if ( forcekill && h != INVALID_HANDLE_VALUE ) {
            Sleep(200);
            TerminateProcess(h, 9);
        }

        if ( h != INVALID_HANDLE_VALUE ) {
            CloseHandle(h);
            child_process_handle_ = INVALID_HANDLE_VALUE;
        }
#else
        if ( kill(childpid, 0) == 0 ) {

            kill(-childpid, SIGTERM);

            if ( forcekill ) {
                usleep(200);

                if ( kill(childpid, 0) == 0 )
                    kill(-childpid, SIGKILL);
            }
        }
#endif
    }
}

void Raw::ClosePipeEnd(int i) {
    if ( pipes[i] == -1 )
        return;

    util::safe_close(pipes[i]);
    pipes[i] = -1;
}

bool Raw::SetFDFlags(int fd, int cmd, int flags) {
    if ( fcntl(fd, cmd, flags) != -1 )
        return true;

    char buf[256];
    util::zeek_strerror_r(errno, buf, sizeof(buf));
    Error(Fmt("failed to set fd flags: %s", buf));
    return false;
}

std::unique_lock<std::mutex> Raw::AcquireForkMutex() {
    auto lock = plugin::detail::Zeek_RawReader::plugin.ForkMutex();

    try {
        lock.lock();
    }

    catch ( const std::system_error& e ) {
        reporter->FatalErrorWithCore("cannot lock fork mutex: %s", e.what());
    }

    return lock;
}

bool Raw::Execute() {
#ifdef _MSC_VER


    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;


    HANDLE hStdoutReadRaw, hStdoutWriteRaw;
    if ( ! CreatePipe(&hStdoutReadRaw, &hStdoutWriteRaw, &sa, 0) ) {
        Error(Fmt("Failed to create stdout pipe: %lu", GetLastError()));
        return false;
    }
    UniqueHandle hStdoutRead(hStdoutReadRaw);
    UniqueHandle hStdoutWrite(hStdoutWriteRaw);
    SetHandleInformation(hStdoutRead.get(), HANDLE_FLAG_INHERIT, 0);


    UniqueHandle hStderrRead;
    UniqueHandle hStderrWrite;
    if ( use_stderr ) {
        HANDLE r, w;
        if ( ! CreatePipe(&r, &w, &sa, 0) ) {
            Error(Fmt("Failed to create stderr pipe: %lu", GetLastError()));
            return false;
        }
        hStderrRead.reset(r);
        hStderrWrite.reset(w);
        SetHandleInformation(hStderrRead.get(), HANDLE_FLAG_INHERIT, 0);
    }


    HANDLE hStdinReadRaw, hStdinWriteRaw;
    if ( ! CreatePipe(&hStdinReadRaw, &hStdinWriteRaw, &sa, 0) ) {
        Error(Fmt("Failed to create stdin pipe: %lu", GetLastError()));
        return false;
    }
    UniqueHandle hStdinRead(hStdinReadRaw);
    UniqueHandle hStdinWrite(hStdinWriteRaw);
    SetHandleInformation(hStdinWrite.get(), HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdoutWrite.get();
    si.hStdError = use_stderr ? hStderrWrite.get() : GetStdHandle(STD_ERROR_HANDLE);
    si.hStdInput = hStdinRead.get();




    char cmdline[MAX_PATH] = "bash";




    char bash_path[MAX_PATH] = {};
    const char* app_name = nullptr;
    char path_env[32768];
    DWORD plen = GetEnvironmentVariableA("PATH", path_env, sizeof(path_env));
    if ( plen > 0 && plen < sizeof(path_env) ) {
        if ( SearchPathA(path_env, "bash.exe", nullptr, MAX_PATH, bash_path, nullptr) )
            app_name = bash_path;
    }

    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessA(app_name, cmdline, nullptr, nullptr, TRUE, CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED,
                             nullptr, nullptr, &si, &pi);


    hStdoutWrite.reset();
    if ( use_stderr )
        hStderrWrite.reset();
    hStdinRead.reset();

    if ( ! ok ) {
        Error(Fmt("Failed to create process: %lu", GetLastError()));
        return false;
    }

    UniqueHandle hProcess(pi.hProcess);
    UniqueHandle hThread(pi.hThread);



    UniqueHandle job(CreateJobObjectA(nullptr, nullptr));
    if ( job ) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
        AssignProcessToJobObject(job.get(), hProcess.get());
        child_job_handle_ = job.release();
    }

    ResumeThread(hThread.get());
    hThread.reset();

    childpid = static_cast<int>(pi.dwProcessId);
    child_process_handle_ = hProcess.release();







    std::string cmd_input = "tail() { command tail ---disable-inotify -s 0.5 \"$@\"; }\n" + fname + "\n";
    DWORD written;
    WriteFile(hStdinWrite.get(), cmd_input.c_str(), static_cast<DWORD>(cmd_input.size()), &written, nullptr);

    if ( stdin_towrite ) {
        WriteFile(hStdinWrite.get(), stdin_string.c_str(), static_cast<DWORD>(stdin_string.size()), &written, nullptr);
        stdin_towrite = 0;
    }

    hStdinWrite.reset();


    int stdout_fd = _open_osfhandle(reinterpret_cast<intptr_t>(hStdoutRead.get()), _O_RDONLY);
    if ( stdout_fd == -1 ) {
        Error("Could not convert stdout handle to file descriptor");
        return false;
    }
    hStdoutRead.release();

    file = std::unique_ptr<FILE, int (*)(FILE*)>(_fdopen(stdout_fd, "rb"), fclose);
    if ( ! file ) {
        Error("Could not convert stdout fd to FILE");
        _close(stdout_fd);
        return false;
    }

    if ( use_stderr ) {
        int stderr_fd = _open_osfhandle(reinterpret_cast<intptr_t>(hStderrRead.get()), _O_RDONLY);
        if ( stderr_fd == -1 ) {
            Error("Could not convert stderr handle to file descriptor");
            return false;
        }
        hStderrRead.release();

        stderrfile = std::unique_ptr<FILE, int (*)(FILE*)>(_fdopen(stderr_fd, "rb"), fclose);
        if ( ! stderrfile ) {
            Error("Could not convert stderr fd to FILE");
            _close(stderr_fd);
            return false;
        }
    }

    return true;
#else








    auto lock = AcquireForkMutex();

    if ( pipe(pipes) != 0 || pipe(pipes + 2) || pipe(pipes + 4) ) {
        Error(Fmt("Could not open pipe: %d", errno));
        return false;
    }

    short spawn_flags = 0;

    spawn_flags |= POSIX_SPAWN_SETPGROUP;

    posix_spawn_file_actions_t actions;
    if ( posix_spawn_file_actions_init(&actions) != 0 ) {
        Error(Fmt("Could not call posix_spawn_file_actions_init: %d", errno));
        return false;
    }

    auto file_actions_res = posix_spawn_file_actions_addclose(&actions, pipes[stdout_in]);
    file_actions_res |= posix_spawn_file_actions_adddup2(&actions, pipes[stdout_out], stdout_fileno);
    file_actions_res |= posix_spawn_file_actions_addclose(&actions, pipes[stdout_out]);
    file_actions_res |= posix_spawn_file_actions_addclose(&actions, pipes[stdin_out]);
    file_actions_res |= posix_spawn_file_actions_adddup2(&actions, pipes[stdin_in], stdin_fileno);
    file_actions_res |= posix_spawn_file_actions_addclose(&actions, pipes[stdin_in]);
    file_actions_res |= posix_spawn_file_actions_addclose(&actions, pipes[stderr_in]);
    file_actions_res |= posix_spawn_file_actions_adddup2(&actions, pipes[stderr_out], stderr_fileno);
    file_actions_res |= posix_spawn_file_actions_addclose(&actions, pipes[stderr_out]);

    if ( file_actions_res != 0 ) {
        Error("Error during posix_spawn_file_actions_add");
        posix_spawn_file_actions_destroy(&actions);
        return false;
    }

    posix_spawnattr_t attrs;
    if ( posix_spawnattr_init(&attrs) != 0 ) {
        Error(Fmt("Could not call posix_spawnattr_init: %d", errno));
        posix_spawn_file_actions_destroy(&actions);
        return false;
    }


    posix_spawnattr_setflags(&attrs, spawn_flags);






    sigset_t mask;
    sigemptyset(&mask);
    spawn_flags |= POSIX_SPAWN_SETSIGMASK;

    posix_spawnattr_setsigmask(&attrs, &mask);

    spawn_flags |= POSIX_SPAWN_SETSIGDEF;
    sigset_t sigdefault;
    sigemptyset(&sigdefault);
    sigaddset(&sigdefault, SIGPIPE);

    posix_spawnattr_setsigdefault(&attrs, &sigdefault);

    const char* spawn_argv[] = {"sh", "-c", fname.c_str(), nullptr};
    auto posix_spawn_res = posix_spawn(&childpid, "/bin/sh", &actions, &attrs, const_cast<char**>(spawn_argv), environ);

    posix_spawnattr_destroy(&attrs);
    posix_spawn_file_actions_destroy(&actions);

    if ( posix_spawn_res != 0 ) {
        Error(Fmt("Could not spawn child process: %d", errno));
        return false;
    }

    lock.unlock();

    ClosePipeEnd(stdout_out);

    if ( Info().mode == MODE_STREAM ) {
        if ( ! SetFDFlags(pipes[stdout_in], F_SETFL, O_NONBLOCK) )
            return false;
    }

    ClosePipeEnd(stdin_in);

    if ( stdin_towrite ) {








        if ( ! SetFDFlags(pipes[stdin_out], F_SETFL, O_NONBLOCK) )
            return false;
    }
    else
        ClosePipeEnd(stdin_out);

    ClosePipeEnd(stderr_out);

    if ( use_stderr ) {
        if ( ! SetFDFlags(pipes[stderr_in], F_SETFL, O_NONBLOCK) )
            return false;
    }
    else
        ClosePipeEnd(stderr_in);

    file = std::unique_ptr<FILE, int (*)(FILE*)>(fdopen(pipes[stdout_in], "r"), fclose);

    if ( ! file ) {
        Error("Could not convert stdout_in fileno to file");
        return false;
    }

    pipes[stdout_in] = -1;

    if ( use_stderr ) {
        stderrfile = std::unique_ptr<FILE, int (*)(FILE*)>(fdopen(pipes[stderr_in], "r"), fclose);

        if ( ! stderrfile ) {
            Error("Could not convert stderr_in fileno to file");
            return false;
        }

        pipes[stderr_in] = -1;
    }

    return true;
#endif
}

bool Raw::OpenInput() {
    if ( execute )
        return Execute();

    else {
        file = std::unique_ptr<FILE, int (*)(FILE*)>(zeek::input::reader::detail::fopen_with_share_delete(fname.c_str(),
                                                                                                          "r"),
                                                     fclose);
        if ( ! file ) {
            if ( Info().mode == MODE_STREAM )

                return true;

            Error(Fmt("Init: cannot open %s", fname.c_str()));
            return false;
        }

        if ( Info().mode == MODE_STREAM || Info().mode == MODE_REREAD ) {
            struct stat sb;




            if ( stat(fname.c_str(), &sb) == -1 ) {
                Error(Fmt("Could not get stat for %s", fname.c_str()));
                return false;
            }

            mtime = sb.st_mtime;
            ino = reliable_inode(fname.c_str(), sb.st_ino);
            dev = sb.st_dev;
            fsize = sb.st_size;
        }

        if ( ! SetFDFlags(fileno(file.get()), F_SETFD, FD_CLOEXEC) )
            Warning(Fmt("Init: cannot set close-on-exec for %s", fname.c_str()));
    }

    if ( offset ) {
        int whence = (offset >= 0) ? SEEK_SET : SEEK_END;
        int64_t pos = (offset >= 0) ? offset : offset + 1;

        if ( fseek(file.get(), pos, whence) < 0 ) {
            char buf[256];
            util::zeek_strerror_r(errno, buf, sizeof(buf));
            Error(Fmt("Seek failed in init: %s", buf));
        }
    }

    return true;
}

bool Raw::CloseInput() {
    if ( ! file ) {
        InternalWarning(Fmt("Trying to close closed file for stream %s", fname.c_str()));
        return false;
    }
#ifdef DEBUG
    Debug(DBG_INPUT, "Raw reader starting close");
#endif

    file.reset(nullptr);

    if ( use_stderr )
        stderrfile.reset(nullptr);

    if ( execute ) {
        for ( int i = 0; i < 6; i++ )
            ClosePipeEnd(i);
    }

#ifdef DEBUG
    Debug(DBG_INPUT, "Raw reader finished close");
#endif

    return true;
}

bool Raw::DoInit(const ReaderInfo& info, int num_fields, const Field* const* fields) {
    if ( ! info.source || strlen(info.source) == 0 ) {
        Error("No source path provided");
        return false;
    }

    fname = info.source;
    mtime = 0;
    ino = 0;
    dev = 0;
    fsize = 0;
    execute = false;
    firstrun = true;
    int want_fields = 1;
    bool result;

    std::string source = std::string(info.source);
    char last = info.source[source.length() - 1];
    if ( last == '|' ) {
        execute = true;
        fname = source.substr(0, fname.length() - 1);
    }

    ReaderInfo::config_map::const_iterator it = info.config.find("stdin");
    if ( it != info.config.end() ) {
        stdin_string = it->second;
        stdin_towrite = stdin_string.length();
    }

    it = info.config.find("read_stderr");
    if ( it != info.config.end() && execute ) {
        use_stderr = true;
        want_fields = 2;
    }

    it = info.config.find("force_kill");
    if ( it != info.config.end() && execute ) {
        forcekill = true;
    }

    it = info.config.find("offset");
    if ( it != info.config.end() && ! execute && (Info().mode == MODE_STREAM || Info().mode == MODE_MANUAL) ) {
        std::string offset_s = it->second;
        offset = strtoll(offset_s.c_str(), nullptr, 10);
    }
    else if ( it != info.config.end() ) {
        Error(
            "Offset only is supported for MODE_STREAM and MODE_MANUAL; it is also not supported "
            "when executing a command");
        return false;
    }

    if ( num_fields != want_fields ) {
        Error(
            Fmt("Filter for raw reader contains wrong number of fields -- got %d, expected %d. "
                "Filters for the raw reader contain one string field when used in normal mode and "
                "one string and one bool fields when using execute mode with stderr capturing. "
                "Filter ignored.",
                num_fields, want_fields));
        return false;
    }

    if ( fields[0]->type != TYPE_STRING ) {
        Error("First field for raw reader always has to be of type string.");
        return false;
    }
    if ( use_stderr && fields[1]->type != TYPE_BOOL ) {
        Error("Second field for raw reader always has to be of type bool.");
        return false;
    }

    if ( execute && Info().mode == MODE_REREAD ) {

        Error("Rereading only supported for files, not for executables.");
        return false;
    }

    result = OpenInput();

    if ( result == false )
        return result;

#ifdef DEBUG
    Debug(DBG_INPUT, "Raw reader created, will perform first update");
#endif


    DoUpdate();

#ifdef DEBUG
    Debug(DBG_INPUT, "First update went through");
#endif
    return true;
}

int64_t Raw::GetLine(FILE* arg_file) {
    errno = 0;

    if ( ! buf ) {
        buf = std::unique_ptr<char[]>(new char[block_size]);
        bufpos = 0;
        bufsize = block_size;
    }

    for ( ;; ) {
#ifdef _MSC_VER







        size_t readbytes;
        bool at_eof = false;
        if ( execute && Info().mode == MODE_STREAM ) {
            int fd = _fileno(arg_file);
            HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
            DWORD avail = 0;
            if ( PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr) ) {
                if ( avail == 0 && bufpos == 0 )
                    return -2;
                if ( avail == 0 ) {
                    readbytes = 0;
                }
                else {
                    unsigned int to_read = std::min<unsigned int>(bufsize - bufpos, avail);
                    int r = _read(fd, buf.get() + bufpos, to_read);
                    readbytes = (r > 0) ? static_cast<size_t>(r) : 0;
                    if ( r == 0 )
                        at_eof = true;
                }
            }
            else {



                unsigned int to_read = static_cast<unsigned int>(bufsize - bufpos);
                int r = (to_read > 0) ? _read(fd, buf.get() + bufpos, to_read) : 0;
                readbytes = (r > 0) ? static_cast<size_t>(r) : 0;
                if ( r <= 0 )
                    at_eof = true;
            }
        }
        else {
            readbytes = fread(buf.get() + bufpos, 1, bufsize - bufpos, arg_file);
        }
#else
        size_t readbytes = fread(buf.get() + bufpos, 1, bufsize - bufpos, arg_file);
#endif

        bufpos = bufpos + readbytes;


        if ( bufpos == 0 && errno != 0 )
            break;






        int found = util::strstr_n(bufpos, reinterpret_cast<u_char*>(buf.get()), separator.size(),
                                   reinterpret_cast<const u_char*>(separator.c_str()));

        if ( found == -1 ) {


#ifdef _MSC_VER

            bool is_eof = at_eof || feof(arg_file) != 0;
#else
            bool is_eof = feof(arg_file) != 0;
#endif
            if ( is_eof ) {
                if ( bufpos == 0 )
                    return -1;
                else {
                    outbuf = std::move(buf);
                    return bufpos;
                }
            }


            if ( bufpos == bufsize ) {
                std::unique_ptr<char[]> newbuf = std::unique_ptr<char[]>(new char[bufsize + block_size]);
                memcpy(newbuf.get(), buf.get(), bufsize);
                buf = std::move(newbuf);
                bufsize = bufsize + block_size;
            }
            else {



                return -2;
            }
        }
        else {
            size_t sep_idx = static_cast<size_t>(found);
            assert(sep_idx <= bufsize - sep_length);
            size_t remaining = bufpos - sep_idx - sep_length;

            outbuf = std::move(buf);

            if ( remaining > 0 ) {

                assert(remaining <= block_size);
                buf = std::unique_ptr<char[]>(new char[block_size]);
                bufpos = remaining;
                bufsize = block_size;

                memcpy(buf.get(), outbuf.get() + sep_idx + sep_length, remaining);
            }

            return sep_idx;
        }
    }

    if ( errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR )
        return -2;

    else {

        Error(Fmt("Reader encountered unexpected error code %d", errno));
        return -3;
    }
}


void Raw::WriteToStdin() {
    assert(stdin_towrite <= stdin_string.length());
    uint64_t pos = stdin_string.length() - stdin_towrite;

    errno = 0;
    ssize_t written = write(pipes[stdin_out], stdin_string.c_str() + pos, stdin_towrite);
    stdin_towrite -= written;

    if ( errno != 0 && errno != EAGAIN && errno != EWOULDBLOCK ) {
        Error(Fmt("Writing to child process stdin failed: %d. Stopping writing at position %" PRIu64, errno, pos));
        stdin_towrite = 0;
    }

    if ( stdin_towrite == 0 )
        ClosePipeEnd(stdin_out);

    if ( Info().mode == MODE_MANUAL && stdin_towrite != 0 ) {
        Error(
            Fmt("Could not write whole string to stdin of child process in one go. Please use "
                "STREAM mode to pass more data to child."));
    }
}


bool Raw::DoUpdate() {
    if ( firstrun )
        firstrun = false;

    else {
        switch ( Info().mode ) {
            case MODE_REREAD: {
                assert(childpid == -1);

                struct stat sb;
                if ( stat(fname.c_str(), &sb) == -1 ) {
                    Error(Fmt("Could not get stat for %s", fname.c_str()));
                    return false;
                }

                file_ino_t current_ino = reliable_inode(fname.c_str(), sb.st_ino);

                if ( sb.st_dev == dev && current_ino == ino && sb.st_mtime == mtime && sb.st_size == fsize )

                    return true;

                mtime = sb.st_mtime;
                ino = current_ino;
                dev = sb.st_dev;
                fsize = sb.st_size;



            }

            case MODE_MANUAL:
                CloseInput();
                if ( ! OpenInput() )
                    return false;

                break;

            case MODE_STREAM:

                if ( file )
                    clearerr(file.get());


                if ( execute )
                    break;


                struct stat sb;
                if ( stat(fname.c_str(), &sb) == -1 )

                    break;



                {
                    file_ino_t current_ino = reliable_inode(fname.c_str(), sb.st_ino);
                    if ( file && current_ino == ino && sb.st_dev == dev )
                        break;
                }


                FILE* tfile;
                tfile = zeek::input::reader::detail::fopen_with_share_delete(fname.c_str(), "r");
                if ( ! tfile )
                    break;



                if ( stat(fname.c_str(), &sb) == -1 ) {
                    Error(Fmt("Could not stat %s", fname.c_str()));
                    fclose(tfile);
                    return false;
                }
                if ( file )
                    file.reset(nullptr);
                file = std::unique_ptr<FILE, int (*)(FILE*)>(tfile, fclose);
                ino = reliable_inode(fname.c_str(), sb.st_ino);
                dev = sb.st_dev;
                offset = 0;
                bufpos = 0;
                break;

            default: assert(false);
        }
    }

    assert((NumFields() == 1 && ! use_stderr) || (NumFields() == 2 && use_stderr));
    for ( ;; ) {
        if ( stdin_towrite > 0 )
            WriteToStdin();

        if ( ! file && Info().mode == MODE_STREAM )

            break;

        int64_t length = GetLine(file.get());

        if ( length == -3 )
            return false;

        else if ( length == -2 || length == -1 )

            break;

        Value** fields = new Value*[2];



        Value* val = new Value(TYPE_STRING, true);
        val->val.string_val.data = outbuf.release();
        val->val.string_val.length = length;
        fields[0] = val;

        if ( use_stderr ) {
            Value* bval = new Value(TYPE_BOOL, true);
            bval->val.int_val = 0;
            fields[1] = bval;
        }

        Put(fields);
    }

    if ( use_stderr ) {
        for ( ;; ) {
            int64_t length = GetLine(stderrfile.get());

            if ( length == -3 )
                return false;

            else if ( length == -2 || length == -1 )
                break;

            Value** fields = new Value*[2];
            Value* val = new Value(TYPE_STRING, true);
            val->val.string_val.data = outbuf.release();
            val->val.string_val.length = length;
            fields[0] = val;
            Value* bval = new Value(TYPE_BOOL, true);
            bval->val.int_val = 1;
            fields[1] = bval;

            Put(fields);
        }
    }

    if ( (Info().mode == MODE_MANUAL) || (Info().mode == MODE_REREAD) )

        EndCurrentSend();


    int return_code;
#ifdef _MSC_VER
    HANDLE h = static_cast<HANDLE>(child_process_handle_);
    DWORD win_exit_code = 0;
    bool child_exited = childpid != -1 && h != INVALID_HANDLE_VALUE && WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
    if ( child_exited )
        GetExitCodeProcess(h, &win_exit_code);
    if ( child_exited ) {
        CloseHandle(h);
        child_process_handle_ = INVALID_HANDLE_VALUE;
        childpid = -1;
        bool signal = false;
        int code = static_cast<int>(win_exit_code);
        if ( code != 0 )
            Error(Fmt("Child process exited with non-zero return code %d", code));
#else
    if ( childpid != -1 && waitpid(childpid, &return_code, WNOHANG) != 0 ) {

        childpid = -1;
        bool signal = false;
        int code = 0;
        if ( WIFEXITED(return_code) ) {
            code = WEXITSTATUS(return_code);
            if ( code != 0 )
                Error(Fmt("Child process exited with non-zero return code %d", code));
        }

        else if ( WIFSIGNALED(return_code) ) {
            signal = true;
            code = WTERMSIG(return_code);
            Error(Fmt("Child process exited due to signal %d", code));
        }

        else
            assert(false);
#endif

        Value** vals = new Value*[4];
        vals[0] = new Value(TYPE_STRING, true);
        auto val0_len = strlen(Info().name);
        vals[0]->val.string_val.data = util::copy_string(Info().name, val0_len);
        vals[0]->val.string_val.length = val0_len;
        vals[1] = new Value(TYPE_STRING, true);
        auto val1_len = strlen(Info().source);
        vals[1]->val.string_val.data = util::copy_string(Info().source, val1_len);
        vals[1]->val.string_val.length = val1_len;
        vals[2] = new Value(TYPE_COUNT, true);
        vals[2]->val.int_val = code;
        vals[3] = new Value(TYPE_BOOL, true);
        vals[3]->val.int_val = signal;


        if ( Info().mode == MODE_STREAM )
            EndCurrentSend();

        SendEvent("InputRaw::process_finished", 4, vals);
        return false;
    }

#ifdef DEBUG
    Debug(DBG_INPUT, "DoUpdate finished successfully");
#endif

    return true;
}

bool Raw::DoHeartbeat(double network_time, double current_time) {
    switch ( Info().mode ) {
        case MODE_MANUAL:

            break;

        case MODE_REREAD:
        case MODE_STREAM:
#ifdef DEBUG
            Debug(DBG_INPUT, "Starting Heartbeat update");
#endif
            Update();

#ifdef DEBUG
            Debug(DBG_INPUT, "Finished with heartbeat update");
#endif
            break;
        default: assert(false);
    }

    return true;
}

}
