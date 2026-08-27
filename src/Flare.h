

#pragma once

#ifndef _MSC_VER
#include "Pipe.h"
#endif

namespace zeek::detail {

class Flare {
public:






    Flare();





    int FD() const
#ifndef _MSC_VER
    {
        return pipe.ReadFD();
    }
#else
    {
        return recvfd;
    }
#endif






    void Fire(bool signal_safe = false);








    int Extinguish(bool signal_safe = false);

private:
#ifndef _MSC_VER
    Pipe pipe;
#else
    int sendfd, recvfd;
#endif
};

}
