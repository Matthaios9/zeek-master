

#pragma once

#include <string>

#include "zeek/Desc.h"
#include "zeek/threading/Formatter.h"

namespace zeek::json::detail {
class NullDoubleWriter;
}

namespace zeek::threading::formatter {





class JSON : public Formatter {
public:
    enum TimeFormat : uint8_t {
        TS_EPOCH,
        TS_ISO8601,
        TS_MILLIS,

        TS_MILLIS_UNSIGNED
    };

    enum StringEscapePolicy : uint8_t {
        STRING_ESCAPE_POLICY_HEX,
        STRING_ESCAPE_POLICY_PUA,
        STRING_ESCAPE_POLICY_TSV,
    };

    JSON(MsgThread* t, TimeFormat tf, bool include_unset_fields = false,
         StringEscapePolicy string_escape_policy = STRING_ESCAPE_POLICY_HEX);

    bool Describe(ODesc* desc, Value* val, const std::string& name = "") const override;
    bool Describe(ODesc* desc, int num_fields, const Field* const* fields, Value** vals) const override;
    Value* ParseValue(const std::string& s, const std::string& name, TypeTag type,
                      TypeTag subtype = TYPE_ERROR) const override;

private:
    void BuildJSON(zeek::json::detail::NullDoubleWriter& writer, Value* val, const std::string& name = "") const;

    TimeFormat timestamps;
    bool include_unset_fields;
    StringEscapePolicy string_escape_policy;


    mutable ODesc desc;
};

}
