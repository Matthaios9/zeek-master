

#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "zeek/Type.h"
#include "zeek/net_util.h"

namespace zeek::detail {
class SerializationFormat;
}

namespace zeek::threading {




struct Field {
    const char* name = nullptr;


    const char* secondary_name = nullptr;
    TypeTag type = TYPE_ERROR;
    TypeTag subtype = TYPE_ERROR;
    bool optional = false;







    Field() = default;




    Field(const char* name, const char* secondary_name, TypeTag type, TypeTag subtype, bool optional)
        : name(util::copy_string(name)),
          secondary_name(util::copy_string(secondary_name)),
          type(type),
          subtype(subtype),
          optional(optional) {}




    Field(const Field& other)
        : name(util::copy_string(other.name)),
          secondary_name(util::copy_string(other.secondary_name)),
          type(other.type),
          subtype(other.subtype),
          optional(other.optional) {}




    Field(Field&& other) noexcept {
        name = other.name;
        secondary_name = other.secondary_name;
        type = other.type;
        subtype = other.subtype;
        optional = other.optional;

        other.name = nullptr;
        other.secondary_name = nullptr;
        other.type = TYPE_ERROR;
        other.subtype = TYPE_ERROR;
        other.optional = false;
    }

    ~Field() {
        delete[] name;
        delete[] secondary_name;
    }

    Field& operator=(const Field& other) {
        if ( this != &other ) {
            delete[] name;
            delete[] secondary_name;
            name = util::copy_string(other.name);
            secondary_name = util::copy_string(other.secondary_name);
            type = other.type;
            subtype = other.subtype;
            optional = other.optional;
        }

        return *this;
    }









    bool Read(zeek::detail::SerializationFormat* fmt);









    bool Write(zeek::detail::SerializationFormat* fmt) const;





    std::string TypeName() const;
};







struct Value {
    TypeTag type;
    TypeTag subtype;
    bool present = false;
    bool truncated = false;



    int32_t line_number = -1;

    struct set_t {
        zeek_int_t size;
        Value** vals;
    };
    using vec_t = set_t;
    struct port_t {
        zeek_uint_t port;
        TransportProto proto;
        constexpr size_t size() { return sizeof(port) + sizeof(proto); }
    };

    struct addr_t {
        IPFamily family;
        union {
            struct in_addr in4;
            struct in6_addr in6;
        } in;

        constexpr size_t size() { return sizeof(in) + sizeof(IPFamily); }
    };








    struct subnet_t {
        addr_t prefix;
        uint8_t length;
        constexpr size_t size() { return prefix.size() + sizeof(length); }
    };





    union _val {
        zeek_int_t int_val;
        zeek_uint_t uint_val;
        port_t port_val;
        double double_val;
        set_t set_val;
        vec_t vector_val;
        addr_t addr_val;
        subnet_t subnet_val;
        struct {
            [[deprecated("Remove in v9.1. Use pattern_val.text instead.")]] const char* pattern_text_val;
        };
        struct {
            const char* text;
            bool is_case_insensitive;
            bool is_single_line;
        } pattern_val;

        struct {
            char* data;
            int length;
        } string_val;

        _val() { memset(static_cast<void*>(this), 0, sizeof(_val)); }
    } val;









    Value(TypeTag arg_type = TYPE_ERROR, bool arg_present = true)
        : type(arg_type), subtype(TYPE_VOID), present(arg_present) {}











    Value(TypeTag arg_type, TypeTag arg_subtype, bool arg_present = true)
        : type(arg_type), subtype(arg_subtype), present(arg_present) {}




    Value(const Value& other);




    Value(Value&& other) noexcept;




    ~Value();








    bool Read(zeek::detail::SerializationFormat* fmt);









    bool Write(zeek::detail::SerializationFormat* fmt) const;





    static bool IsCompatibleType(Type* t, bool atomic_only = false);






    static void delete_value_ptr_array(Value** vals, int num_fields);













    static Val* ValueToVal(const std::string& source, const threading::Value* val, bool& have_error);

    void SetFileLineNumber(int line) { line_number = line; }
    int GetFileLineNumber() const { return line_number; }
};

}
