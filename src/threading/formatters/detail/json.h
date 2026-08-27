


#pragma once

#include <rapidjson/document.h>
#include <rapidjson/internal/ieee754.h>
#include <rapidjson/writer.h>

namespace zeek::json::detail {

class NullDoubleWriter : public rapidjson::Writer<rapidjson::StringBuffer> {
public:
    explicit NullDoubleWriter(rapidjson::StringBuffer& stream) : rapidjson::Writer<rapidjson::StringBuffer>(stream) {}




    bool Double(double d) {
        if ( rapidjson::internal::Double(d).IsNanOrInf() )
            return rapidjson::Writer<rapidjson::StringBuffer>::Null();

        return rapidjson::Writer<rapidjson::StringBuffer>::Double(d);
    }
};

}
