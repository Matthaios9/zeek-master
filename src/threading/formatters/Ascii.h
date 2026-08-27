

#pragma once

#include "zeek/threading/Formatter.h"

namespace zeek::threading::formatter {

class Ascii final : public Formatter {
public:




    struct SeparatorInfo {
        std::string separator;
        std::string set_separator;
        std::string unset_field;
        std::string empty_field;





        SeparatorInfo(const std::string& separator, const std::string& set_separator, const std::string& unset_field,
                      const std::string& empty_field);






        SeparatorInfo();
    };











    Ascii(MsgThread* t, const SeparatorInfo& info);

    bool Describe(ODesc* desc, Value* val, const std::string& name = "") const override;
    bool Describe(ODesc* desc, int num_fields, const Field* const* fields, Value** vals) const override;
    Value* ParseValue(const std::string& s, const std::string& name, TypeTag type,
                      TypeTag subtype = TYPE_ERROR) const override;

private:
    bool CheckNumberError(const char* start, const char* end, bool nonneg_only = false) const;

    SeparatorInfo separators;
};

}
