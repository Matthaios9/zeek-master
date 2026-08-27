

#pragma once

#include "zeek/zeek-config.h"

#include <unistd.h>
#include <atomic>
#include <cstdint>
#include <thread>

namespace zeek::threading {

class Manager;









class BasicThread {
public:









    BasicThread();

    BasicThread(BasicThread const&) = delete;
    BasicThread& operator=(BasicThread const&) = delete;






    virtual ~BasicThread();







    const char* Name() const { return name; }









    void SetName(const char* name);







    void SetOSName(const char* name);








    void Start();














    void SignalStop();










    void WaitForStop();






    bool Terminating() const { return terminating; }






    bool Killed() const { return killed; }







    const char* Fmt(const char* format, ...) __attribute__((format(printf, 2, 3)));







    const char* Strerror(int err);

protected:
    friend class Manager;








    virtual void Run() = 0;






    virtual void OnStart() {}






    virtual void OnSignalStop() {}







    virtual void OnWaitForStop() = 0;




    virtual void OnKill() {}





    void Join();








    void Kill();


    ZEEK_DISABLE_TSAN void Done();

private:

    static void* launcher(void* arg);

    const char* name;
    std::thread thread;
    bool started;
    std::atomic_bool terminating;
    std::atomic_bool killed;


    uint32_t buf_len;
    char* buf;


    char* strerr_buffer;

    static uint64_t thread_counter;
};

}
