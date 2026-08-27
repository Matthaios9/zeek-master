

#pragma once

#include <string>

namespace zeek {

class Packet;

namespace iosource {




class PktDumper {
public:



    PktDumper();




    virtual ~PktDumper() = default;




    const std::string& Path() const;




    bool IsOpen() const;




    double OpenTime() const;




    bool IsError() const;





    const char* ErrorMsg() const;










    virtual void Open() = 0;








    virtual void Close() = 0;











    virtual bool Dump(const Packet* pkt) = 0;

protected:
    friend class Manager;





    struct Properties {
        std::string path;
        double open_time = 0.0;
    };







    void Opened(const Properties& props);





    void Closed();






    void Error(const std::string& msg);




    void Init();




    void Done();

private:
    bool is_open;
    Properties props;

    std::string errmsg;
};

}
}
