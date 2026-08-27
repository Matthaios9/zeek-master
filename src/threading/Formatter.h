

#pragma once

#include <string>

#include "zeek/Type.h"
#include "zeek/threading/SerialTypes.h"

namespace zeek::threading {

class MsgThread;






class Formatter {
public:








    explicit Formatter(MsgThread* t);




    virtual ~Formatter() = default;

















    virtual bool Describe(ODesc* desc, int num_fields, const Field* const* fields, Value** vals) const = 0;














    virtual bool Describe(ODesc* desc, Value* val, const std::string& name = "") const = 0;













    virtual Value* ParseValue(const std::string& s, const std::string& name, TypeTag type,
                              TypeTag subtype = TYPE_ERROR) const = 0;










    static std::string Render(const Value::addr_t& addr);










    static std::string Render(const Value::subnet_t& subnet);











    static std::string Render(double d);










    static std::string Render(TransportProto proto);












    TransportProto ParseProto(const std::string& proto) const;











    Value::addr_t ParseAddr(const std::string& addr) const;

protected:




    MsgThread* GetThread() const { return thread; }

private:
    MsgThread* thread;
};

}
