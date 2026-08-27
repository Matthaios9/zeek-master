

#include "zeek/telemetry/ProcessStats.h"

#ifdef __APPLE__

#include <libproc.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <sys/resource.h>
#include <unistd.h>
#include <cmath>
#include <cstdlib>

namespace zeek::telemetry::detail {

process_stats get_process_stats() {
    process_stats result;


    {
        mach_task_basic_info info;
        mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
        if ( task_info(mach_task_self(), MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info), &count) ==
             KERN_SUCCESS ) {
            result.rss = static_cast<int64_t>(info.resident_size);
            result.vms = static_cast<int64_t>(info.virtual_size);
        }
    }

    {
        task_thread_times_info info;
        mach_msg_type_number_t count = TASK_THREAD_TIMES_INFO_COUNT;
        if ( task_info(mach_task_self(), TASK_THREAD_TIMES_INFO, reinterpret_cast<task_info_t>(&info), &count) ==
             KERN_SUCCESS ) {

            result.cpu_user += info.user_time.seconds;
            result.cpu_user += ceil(info.user_time.microseconds / 1000.0) / 1000.0;
            result.cpu_system += info.system_time.seconds;
            result.cpu_system += ceil(info.system_time.microseconds / 1000.0) / 1000.0;
        }
    }

    {

        auto suggested_buf_size = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, nullptr, 0);
        if ( suggested_buf_size > 0 ) {
            auto buf_size = suggested_buf_size;
            auto buf = malloc(buf_size);
            auto res = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, buf, buf_size);
            free(buf);
            if ( res > 0 )
                result.fds = static_cast<int64_t>(res / sizeof(proc_fdinfo));
        }
    }

    return result;
}

}

#elif defined(HAVE_LINUX)

#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <atomic>
#include <cstdio>
#include <cstring>

std::atomic<long> global_ticks_per_second;
std::atomic<long> global_page_size;

namespace zeek::telemetry::detail {

int64_t count_entries_in_directory(const char* path) {
    int64_t result = 0;
    if ( auto dptr = opendir(path); dptr != nullptr ) {
        for ( auto entry = readdir(dptr); entry != nullptr; entry = readdir(dptr) ) {
            auto fname = entry->d_name;
            if ( strcmp(".", fname) != 0 && strcmp("..", fname) != 0 )
                ++result;
        }
        closedir(dptr);
    }
    return result;
}






bool load_system_setting(std::atomic<long>& cache_var, long& var, int name, [[maybe_unused]] const char* pretty_name) {
    var = cache_var.load();
    switch ( var ) {
        case -1: return false;
        case 0:
            var = sysconf(name);
            if ( var <= 0 ) {
                var = -1;
                cache_var = var;
                return false;
            }
            else {
                cache_var = var;
                return true;
            }
        default: return true;
    }
}

#define TRY_LOAD(varname, confname) load_system_setting(global_##varname, varname, confname, #confname)

process_stats get_process_stats() {
    process_stats result;

    long ticks_per_second = 0;
    long page_size = 0;

    if ( ! TRY_LOAD(ticks_per_second, _SC_CLK_TCK) || ! TRY_LOAD(page_size, _SC_PAGE_SIZE) )
        return result;

    if ( auto f = fopen("/proc/self/stat", "r") ) {
        unsigned long utime_ticks = 0;
        unsigned long stime_ticks = 0;
        unsigned long vmsize_bytes = 0;
        unsigned long rss_pages = 0;

        auto rd = fscanf(f,
                         "%*d "
                         "%*s "
                         "%*c "
                         "%*d "
                         "%*d "
                         "%*d "
                         "%*d "
                         "%*d "
                         "%*u "
                         "%*u "
                         "%*u "
                         "%*u "
                         "%*u "
                         "%lu "
                         "%lu "
                         "%*d "
                         "%*d "
                         "%*d "
                         "%*d "
                         "%*d "
                         "%*d "
                         "%*u "
                         "%lu "
                         "%lu",
                         &utime_ticks, &stime_ticks, &vmsize_bytes, &rss_pages);
        fclose(f);

        if ( rd != 4 )
            return result;

        result.rss = rss_pages * page_size;
        result.vms = vmsize_bytes;
        result.cpu_user = static_cast<double>(utime_ticks) / ticks_per_second;
        result.cpu_system = static_cast<double>(stime_ticks) / ticks_per_second;

        result.fds = count_entries_in_directory("/proc/self/fd");
    }

    return result;
}

}

#elif defined(__FreeBSD__)




#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <unistd.h>
#include <libprocstat.h>
#include <libutil.h>


namespace zeek::telemetry::detail {

process_stats get_process_stats() {
    process_stats result;

    struct kinfo_proc* kp = kinfo_getproc(getpid());
    if ( kp ) {
        result.vms = kp->ki_size;
        result.rss = kp->ki_rssize * getpagesize();
        result.cpu_user = static_cast<double>(kp->ki_rusage.ru_utime.tv_sec) +
                          (static_cast<double>(kp->ki_rusage.ru_utime.tv_usec) / 1e6);
        result.cpu_system = static_cast<double>(kp->ki_rusage.ru_stime.tv_sec) +
                            (static_cast<double>(kp->ki_rusage.ru_stime.tv_usec) / 1e6);

        struct procstat* procstat = procstat_open_sysctl();
        struct filestat_list* files = procstat_getfiles(procstat, kp, 0);
        struct filestat* file = nullptr;



        STAILQ_FOREACH(file, files, next)
        result.fds++;

        procstat_freefiles(procstat, files);
        procstat_freeprocs(procstat, kp);
        procstat_close(procstat);
    }

    return result;
}

}

#elif defined(_WIN32)




#include <windows.h>
#include <psapi.h>


namespace zeek::telemetry::detail {

process_stats get_process_stats() {
    process_stats result;

    auto proc = GetCurrentProcess();


    {
        PROCESS_MEMORY_COUNTERS pmc;
        if ( GetProcessMemoryInfo(proc, &pmc, sizeof(pmc)) ) {
            result.rss = static_cast<int64_t>(pmc.WorkingSetSize);
            result.vms = static_cast<int64_t>(pmc.PagefileUsage);
        }
    }


    {
        FILETIME creation, exit, kernel, user;
        if ( GetProcessTimes(proc, &creation, &exit, &kernel, &user) ) {

            auto ft_to_seconds = [](const FILETIME& ft) -> double {
                ULARGE_INTEGER li;
                li.LowPart = ft.dwLowDateTime;
                li.HighPart = ft.dwHighDateTime;
                return static_cast<double>(li.QuadPart) / 1e7;
            };

            result.cpu_user = ft_to_seconds(user);
            result.cpu_system = ft_to_seconds(kernel);
        }
    }


    {
        DWORD handle_count = 0;
        if ( GetProcessHandleCount(proc, &handle_count) )
            result.fds = static_cast<int64_t>(handle_count);
    }

    return result;
}

}

#endif
