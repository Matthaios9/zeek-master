

#pragma once

#include "zeek/input/ReaderBackend.h"
#include "zeek/threading/SerialTypes.h"

namespace zeek {

class EnumVal;

namespace input {

class Manager;









class ReaderFrontend {
public:












    ReaderFrontend(const ReaderBackend::ReaderInfo& info, EnumVal* type);






    virtual ~ReaderFrontend();












    void Init(const int arg_num_fields, const threading::Field* const* fields);










    void Update();








    void Stop();













    void SetDisable() { disabled = true; }





    bool Disabled() { return disabled; }







    const char* Name() const;




    const ReaderBackend::ReaderInfo& Info() const {
        assert(info);
        return *info;
    }




    int NumFields() const { return num_fields; }




    const threading::Field* const* Fields() const { return fields; }

protected:
    friend class Manager;

private:
    ReaderBackend* backend;
    ReaderBackend::ReaderInfo* info;
    const threading::Field* const* fields;
    int num_fields;
    bool disabled;
    bool initialized;
    const char* name;
};

}
}
