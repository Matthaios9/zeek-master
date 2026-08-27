

#pragma once

#include <cstdint>

namespace zeek::iosource {





class IOSource {
public:
    enum ProcessFlags : uint8_t { READ = 0x01, WRITE = 0x02 };








    IOSource(bool process_fd = false) : implements_process_fd(process_fd) {}




    virtual ~IOSource() = default;





    bool IsOpen() const { return ! closed; }




    virtual void InitSource() {}





    virtual void Done() {}













    virtual double GetNextTimeout() = 0;







    virtual void Process() = 0;











    virtual void ProcessFd(int fd, int flags) {}
    bool ImplementsProcessFd() const { return implements_process_fd; }








    virtual const char* Tag() = 0;

protected:





    void SetClosed(bool is_closed) { closed = is_closed; }

private:
    bool closed = false;
    bool implements_process_fd = false;
};

}
