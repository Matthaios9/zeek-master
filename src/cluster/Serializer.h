



#pragma once

#include <optional>
#include <span>
#include <string>

#include "zeek/logging/Types.h"

namespace zeek::cluster {

class Event;







class EventSerializer {
public:
    virtual ~EventSerializer() = default;









    virtual bool SerializeEvent(byte_buffer& buf, const cluster::Event& event) = 0;








    virtual std::optional<cluster::Event> UnserializeEvent(byte_buffer_span buf) = 0;




    const std::string& Name() { return name; }

protected:



    EventSerializer(std::string name) : name(std::move(name)) {}

private:
    std::string name;
};




class LogSerializer {
public:



    explicit LogSerializer(std::string name) : name(std::move(name)) {};

    virtual ~LogSerializer() = default;








    virtual bool SerializeLogWrite(byte_buffer& buf, const logging::detail::LogWriteHeader& header,
                                   std::span<logging::detail::LogRecord> records) = 0;






    virtual std::optional<logging::detail::LogWriteBatch> UnserializeLogWrite(byte_buffer_span buf) = 0;




    const std::string& Name() { return name; }

private:
    std::string name;
};

}
