





#pragma once

#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>

#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/profiler.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/type-info.h>
#include <hilti/rt/types/all.h>
#include <hilti/rt/util.h>

#include "zeek/Desc.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/spicy/cookie.h"
#include "zeek/spicy/manager.h"
#include "zeek/spicy/port-range.h"

namespace zeek::spicy::rt {


using UsageError = ::hilti::rt::UsageError;





class ValueUnavailable : public UsageError {
public:
    using UsageError::UsageError;
};





class InvalidValue : public UsageError {
public:
    using UsageError::UsageError;
};





class Unsupported : public UsageError {
public:
    using UsageError::UsageError;
};




class TypeMismatch : public UsageError {
    using UsageError::UsageError;
};





class ParameterMismatch : public TypeMismatch {
public:
    ParameterMismatch(std::string_view msg, std::string_view location = "")
        : TypeMismatch(hilti::rt::fmt("Event parameter mismatch, %s", msg)) {}
    ParameterMismatch(std::string_view have, const TypePtr& want, std::string_view location = "")
        : ParameterMismatch(_fmt(have, want)) {}
    ParameterMismatch(const hilti::rt::TypeInfo& have, const TypePtr& want, std::string_view location = "")
        : ParameterMismatch(_fmt(have.display, want)) {}

private:
    static std::string _fmt(const std::string_view& have, const TypePtr& want) {
        ODesc d;
        want->Describe(&d);
        return hilti::rt::fmt("cannot convert Spicy value of type '%s' to Zeek value of type '%s'", have,
                              d.Description());
    }
};




class ZeekError : public UsageError {
public:
    using UsageError::UsageError;
};





void register_spicy_module_begin(const hilti::rt::String& id, const hilti::rt::String& description);





void register_protocol_analyzer(const hilti::rt::String& id, hilti::rt::Protocol proto,
                                const hilti::rt::Vector<::zeek::spicy::rt::PortRange>& ports,
                                const hilti::rt::String& parser_orig, const hilti::rt::String& parser_resp,
                                const hilti::rt::String& replaces,
                                const hilti::rt::integer::safe<uint64_t>& linker_scope);





void register_file_analyzer(const hilti::rt::String& id, const hilti::rt::Vector<hilti::rt::String>& mime_types,
                            const hilti::rt::String& parser, const hilti::rt::String& replaces,
                            const hilti::rt::integer::safe<uint64_t>& linker_scope);


void weird(const hilti::rt::String& id, const hilti::rt::String& addl);





void register_packet_analyzer(const hilti::rt::String& id, const hilti::rt::String& parser,
                              const hilti::rt::String& replaces,
                              const hilti::rt::integer::safe<uint64_t>& linker_scope);


void register_type(const hilti::rt::String& ns, const hilti::rt::String& id, const TypePtr& type);





void register_spicy_module_end();



enum class ZeekTypeTag : uint8_t {
    Addr,
    Any,
    Bool,
    Count,
    Double,
    Enum,
    Error,
    File,
    Func,
    Int,
    Interval,
    List,
    Opaque,
    Pattern,
    Port,
    Record,
    String,
    Subnet,
    Table,
    Time,
    Type,
    Vector,
    Void,
};

HILTI_RT_ENUM(AnalyzerType, File, Packet, Protocol);

extern TypePtr create_base_type(ZeekTypeTag tag);

extern TypePtr create_enum_type(
    const hilti::rt::String& ns, const hilti::rt::String& id,
    const hilti::rt::Set<hilti::rt::Tuple<hilti::rt::String, hilti::rt::integer::safe<int64_t>>>& labels);

struct RecordField {
    hilti::rt::String id;
    TypePtr type;
    bool is_optional;
    bool is_log;
};

extern TypePtr create_record_type(const hilti::rt::String& ns, const hilti::rt::String& id,
                                  const hilti::rt::Vector<RecordField>& fields);
extern RecordField create_record_field(const hilti::rt::String& id, const TypePtr& type, hilti::rt::Bool is_optional,
                                       hilti::rt::Bool is_log);

extern TypePtr create_table_type(TypePtr key, hilti::rt::Optional<TypePtr> value);
extern TypePtr create_vector_type(const TypePtr& elem);


inline hilti::rt::Bool have_handler(const EventHandlerPtr& handler) { return static_cast<bool>(handler); }




void install_handler(const hilti::rt::String& name);





EventHandlerPtr internal_handler(const hilti::rt::String& name);


void raise_event(const EventHandlerPtr& handler, const hilti::rt::Vector<ValPtr>& args);





TypePtr event_arg_type(const EventHandlerPtr& handler, const hilti::rt::integer::safe<uint64_t>& idx);







zeek::analyzer::ID current_analyzer_id();







ValPtr& current_conn();







ValPtr& current_is_orig();







void debug(const Cookie& cookie, std::string_view msg);







void debug(std::string_view msg);







ValPtr current_file();







ValPtr current_packet();





hilti::rt::Bool is_orig();




hilti::rt::String uid();




hilti::rt::Tuple<hilti::rt::Address, hilti::rt::Port, hilti::rt::Address, hilti::rt::Port> conn_id();


void flip_roles();





hilti::rt::integer::safe<uint64_t> number_packets();






void confirm_protocol();







void reject_protocol(const hilti::rt::String& reason = hilti::rt::String("protocol rejected"));




class ProtocolHandle {
public:
    ProtocolHandle() = default;
    explicit ProtocolHandle(uint64_t id, ::hilti::rt::Protocol proto) : _id(id), _proto(proto) {}

    uint64_t id() const {
        if ( ! _id )
            throw ValueUnavailable("uninitialized protocol handle");

        return *_id;
    }

    const auto& protocol() const { return _proto; }

    friend std::string to_string(const ProtocolHandle& h, ::hilti::rt::detail::adl::tag) {
        if ( ! h._id )
            return "(uninitialized protocol handle)";

        return std::to_string(*h._id);
    }

    friend std::ostream& operator<<(std::ostream& stream, const ProtocolHandle& h) {
        return stream << ::hilti::rt::to_string(h);
    }

private:
    std::optional<uint64_t> _id;
    ::hilti::rt::Protocol _proto = ::hilti::rt::Protocol::Undef;
};








AnalyzerType analyzer_type(const hilti::rt::String& analyzer, const hilti::rt::Bool& if_enabled);








inline hilti::rt::Bool has_analyzer(const hilti::rt::String& analyzer, const hilti::rt::Bool& if_enabled) {
    return analyzer_type(analyzer, if_enabled) != AnalyzerType::Undef;
}






void protocol_begin(const hilti::rt::Optional<hilti::rt::String>& analyzer, const ::hilti::rt::Protocol& proto);






void protocol_begin(const ::hilti::rt::Protocol& proto);













rt::ProtocolHandle protocol_handle_get_or_create(const hilti::rt::String& analyzer, const ::hilti::rt::Protocol& proto);









void protocol_data_in(const hilti::rt::Bool& is_orig, const hilti::rt::Bytes& data, const ::hilti::rt::Protocol& proto);









void protocol_data_in(const hilti::rt::Bool& is_orig, const hilti::rt::Bytes& data, const ProtocolHandle& h);










void protocol_gap(const hilti::rt::Bool& is_orig, const hilti::rt::integer::safe<uint64_t>& offset,
                  const hilti::rt::integer::safe<uint64_t>& len, const hilti::rt::Optional<ProtocolHandle>& h = {});





void protocol_end();






void protocol_handle_close(const ProtocolHandle& handle);









hilti::rt::String file_begin(const hilti::rt::Optional<hilti::rt::String>& mime_type,
                             const hilti::rt::Optional<hilti::rt::String>& fid);




hilti::rt::String fuid();





void terminate_session();





void skip_input();







void file_set_size(const hilti::rt::integer::safe<uint64_t>& size,
                   const hilti::rt::Optional<hilti::rt::String>& fid = {});







void file_data_in(const hilti::rt::Bytes& data, const hilti::rt::Optional<hilti::rt::String>& fid = {});








void file_data_in_at_offset(const hilti::rt::Bytes& data, const hilti::rt::integer::safe<uint64_t>& offset,
                            const hilti::rt::Optional<hilti::rt::String>& fid = {});








void file_gap(const hilti::rt::integer::safe<uint64_t>& offset, const hilti::rt::integer::safe<uint64_t>& len,
              const hilti::rt::Optional<hilti::rt::String>& fid = {});






void file_end(const hilti::rt::Optional<hilti::rt::String>& fid = {});


void forward_packet(const hilti::rt::integer::safe<uint32_t>& identifier);


hilti::rt::Time network_time();

namespace detail {
extern ValPtr to_val(const hilti::rt::type_info::Value& value, const TypePtr& target);
}

template<typename T>
ValPtr to_val(const T& value, const hilti::rt::TypeInfo* type, const TypePtr& target) {
    return detail::to_val(hilti::rt::type_info::Value(&value, type), target);




}





inline ValPtr get_value(const hilti::rt::String& name) {
    if ( auto id = zeek::detail::global_scope()->Find(std::string(name)) )
        return id->GetVal();
    else
        throw InvalidValue(util::fmt("no such Zeek variable: '%s'", std::string(name).c_str()));
}

namespace detail {

inline auto type_mismatch(const ValPtr& v, const char* expected) {
    throw TypeMismatch(util::fmt("type mismatch in Zeek value: expected %s, but got %s", expected,
                                 ::zeek::type_name(v->GetType()->Tag())));
}





inline auto check_type(const ValPtr& v, ::zeek::TypeTag type_tag, const char* expected) {
    if ( v->GetType()->Tag() != type_tag )
        type_mismatch(v, expected);
}

}


using ValRecordPtr = ::zeek::IntrusivePtr<::zeek::RecordVal>;


using ValSetPtr = ::zeek::IntrusivePtr<::zeek::TableVal>;


using ValTablePtr = ::zeek::IntrusivePtr<::zeek::TableVal>;


using ValVectorPtr = ::zeek::IntrusivePtr<::zeek::VectorVal>;


inline ::hilti::rt::Address as_address(const ValPtr& v) {
    detail::check_type(v, TYPE_ADDR, "address");
    return ::hilti::rt::Address(v->AsAddr().AsString());
}


inline ::hilti::rt::Bool as_bool(const ValPtr& v) {
    detail::check_type(v, TYPE_BOOL, "bool");
    return {v->AsBool()};
}


inline hilti::rt::integer::safe<uint64_t> as_count(const ValPtr& v) {
    detail::check_type(v, TYPE_COUNT, "count");
    return v->AsCount();
}


inline double as_double(const ValPtr& v) {
    detail::check_type(v, TYPE_DOUBLE, "double");
    return v->AsDouble();
}





inline hilti::rt::String as_enum(const ValPtr& v) {
    detail::check_type(v, TYPE_ENUM, "enum");




    return hilti::rt::String(hilti::rt::rsplit1(v->GetType()->AsEnumType()->Lookup(v->AsEnum()), "::").second);
}


inline hilti::rt::integer::safe<int64_t> as_int(const ValPtr& v) {
    detail::check_type(v, TYPE_INT, "int");
    return v->AsInt();
}


inline ::hilti::rt::Interval as_interval(const ValPtr& v) {
    detail::check_type(v, TYPE_INTERVAL, "interval");
    return ::hilti::rt::Interval(v->AsInterval(), hilti::rt::Interval::SecondTag{});
}


inline ::hilti::rt::Port as_port(const ValPtr& v) {
    detail::check_type(v, TYPE_PORT, "port");
    auto p = v->AsPortVal();


    return {hilti::rt::integer::safe<uint16_t>(p->Port()), p->PortType()};
}


inline ValRecordPtr as_record(const ValPtr& v) {
    detail::check_type(v, TYPE_RECORD, "record");
    return ::zeek::cast_intrusive<::zeek::RecordVal>(v);
}


inline ValSetPtr as_set(const ValPtr& v) {
    detail::check_type(v, TYPE_TABLE, "set");

    if ( ! v->AsTableVal()->GetType()->IsSet() )
        detail::type_mismatch(v, "set");

    return ::zeek::cast_intrusive<::zeek::TableVal>(v);
}


inline hilti::rt::Bytes as_string(const ValPtr& v) {
    detail::check_type(v, TYPE_STRING, "string");
    auto str = v->AsString();
    return {reinterpret_cast<const char*>(str->Bytes()), static_cast<size_t>(str->Len())};
}


inline ::hilti::rt::Network as_subnet(const ValPtr& v) {
    detail::check_type(v, TYPE_SUBNET, "subnet");
    auto subnet = v->AsSubNet();
    return {subnet.Prefix(), subnet.Length()};
}


inline ValTablePtr as_table(const ValPtr& v) {
    detail::check_type(v, TYPE_TABLE, "table");

    if ( v->AsTableVal()->GetType()->IsSet() )
        detail::type_mismatch(v, "table");

    return ::zeek::cast_intrusive<::zeek::TableVal>(v);
}


inline ::hilti::rt::Time as_time(const ValPtr& v) {
    detail::check_type(v, TYPE_TIME, "time");
    return ::hilti::rt::Time(v->AsTime(), hilti::rt::Time::SecondTag{});
}


inline ValVectorPtr as_vector(const ValPtr& v) {
    detail::check_type(v, TYPE_VECTOR, "vector");
    return ::zeek::cast_intrusive<::zeek::VectorVal>(v);
}



inline hilti::rt::Address get_address(const hilti::rt::String& name) { return as_address(get_value(name)); }


inline hilti::rt::Bool get_bool(const hilti::rt::String& name) { return as_bool(get_value(name)); }


inline hilti::rt::integer::safe<uint64_t> get_count(const hilti::rt::String& name) { return as_count(get_value(name)); }


inline double get_double(const hilti::rt::String& name) { return as_double(get_value(name)); }





inline hilti::rt::String get_enum(const hilti::rt::String& name) { return hilti::rt::String(as_enum(get_value(name))); }


inline hilti::rt::integer::safe<int64_t> get_int(const hilti::rt::String& name) { return as_int(get_value(name)); }


inline hilti::rt::Interval get_interval(const hilti::rt::String& name) { return as_interval(get_value(name)); }


inline hilti::rt::Port get_port(const hilti::rt::String& name) { return as_port(get_value(name)); }


inline ValRecordPtr get_record(const hilti::rt::String& name) { return as_record(get_value(name)); }


inline ValSetPtr get_set(const hilti::rt::String& name) { return as_set(get_value(name)); }


inline hilti::rt::Bytes get_string(const hilti::rt::String& name) { return as_string(get_value(name)); }


inline hilti::rt::Network get_subnet(const hilti::rt::String& name) { return as_subnet(get_value(name)); }


inline ValTablePtr get_table(const hilti::rt::String& name) { return as_table(get_value(name)); }


inline hilti::rt::Time get_time(const hilti::rt::String& name) { return as_time(get_value(name)); }


inline ValVectorPtr get_vector(const hilti::rt::String& name) { return as_vector(get_value(name)); }


inline ::zeek::ValPtr record_field(const zeek::spicy::rt::ValRecordPtr& v, const hilti::rt::String& field) {
    auto index = v->GetType()->AsRecordType()->FieldOffset(std::string(field).c_str());
    if ( index < 0 )
        throw InvalidValue(util::fmt("no such record field: %s", std::string(field).c_str()));

    if ( auto x = v->GetFieldOrDefault(index) )
        return x;
    else
        throw InvalidValue(util::fmt("record field is not set: %s", std::string(field).c_str()));
}


inline ::zeek::ValPtr record_field(const hilti::rt::String& name, const hilti::rt::String& index) {
    return record_field(get_record(name), std::string_view(index));
}


inline hilti::rt::Bool record_has_value(const zeek::spicy::rt::ValRecordPtr& v, std::string_view field) {
    auto index = v->GetType()->AsRecordType()->FieldOffset(std::string(field).c_str());
    if ( index < 0 )
        throw InvalidValue(util::fmt("no such field in record type: %s", std::string(field).c_str()));

    return v->HasField(index);
}


inline hilti::rt::Bool record_has_value(const hilti::rt::String& name, const hilti::rt::String& index) {
    return record_has_value(get_record(name), std::string_view(index));
}


inline hilti::rt::Bool record_has_field(const zeek::spicy::rt::ValRecordPtr& v, const hilti::rt::String& field) {
    return v->GetType()->AsRecordType()->FieldOffset(std::string(field).c_str()) >= 0;
}


inline hilti::rt::Bool record_has_field(const hilti::rt::String& name, const hilti::rt::String& index) {
    return record_has_value(get_record(name), std::string_view(index));
}


template<typename T>
::hilti::rt::Bool set_contains(const ValSetPtr& v, const T& key, const hilti::rt::TypeInfo* ktype) {
    auto index = v->GetType()->AsTableType()->GetIndexTypes()[0];
    return (v->Find(to_val(key, ktype, index)) != nullptr);
}


template<typename T>
::hilti::rt::Bool set_contains(const hilti::rt::String& name, const T& key, const hilti::rt::TypeInfo* ktype) {
    return set_contains(get_set(name), key, ktype);
}


template<typename T>
::hilti::rt::Bool table_contains(const ValTablePtr& v, const T& key, const hilti::rt::TypeInfo* ktype) {
    auto index = v->GetType()->AsTableType()->GetIndexTypes()[0];
    return (v->Find(to_val(key, ktype, index)) != nullptr);
}


template<typename T>
::hilti::rt::Bool table_contains(const hilti::rt::String& name, const T& key, const hilti::rt::TypeInfo* ktype) {
    return table_contains(get_table(name), key, ktype);
}





template<typename T>
hilti::rt::Optional<::zeek::ValPtr> table_lookup(const zeek::spicy::rt::ValTablePtr& v, const T& key,
                                                 const hilti::rt::TypeInfo* ktype) {
    auto index = v->GetType()->AsTableType()->GetIndexTypes()[0];
    if ( auto x = v->FindOrDefault(to_val(key, ktype, index)) )
        return x;
    else
        return {};
}





template<typename T>
hilti::rt::Optional<::zeek::ValPtr> table_lookup(const hilti::rt::String& name, const T& key,
                                                 const hilti::rt::TypeInfo* ktype) {
    return table_lookup(get_table(name), key, ktype);
}


inline ::zeek::ValPtr vector_index(const zeek::spicy::rt::ValVectorPtr& v,
                                   const hilti::rt::integer::safe<uint64_t>& index) {
    if ( index >= v->Size() )
        throw InvalidValue(util::fmt("vector index out of bounds: %" PRIu64, index.Ref()));

    return v->ValAt(index);
}


inline ::zeek::ValPtr vector_index(const hilti::rt::String& name, const hilti::rt::integer::safe<uint64_t>& index) {
    return vector_index(get_vector(name), index);
}


inline hilti::rt::integer::safe<uint64_t> vector_size(const zeek::spicy::rt::ValVectorPtr& v) { return v->Size(); }


inline hilti::rt::integer::safe<uint64_t> vector_size(const hilti::rt::String& name) {
    return vector_size(get_vector(name));
}

}

namespace hilti::rt::detail::adl {

inline std::string to_string(const zeek::ValPtr& v, detail::adl::tag ) { return "<Zeek value>"; }

inline std::string to_string(const zeek::spicy::rt::ValRecordPtr& v, detail::adl::tag ) {
    return "<Zeek record>";
}

inline std::string to_string(const zeek::spicy::rt::ValTablePtr& v, detail::adl::tag ) {
    return "<Zeek set/table>";
}

inline std::string to_string(const zeek::spicy::rt::ValVectorPtr& v, detail::adl::tag ) {
    return "<Zeek vector>";
}

extern std::string to_string(const zeek::spicy::rt::ZeekTypeTag& v, detail::adl::tag );
extern std::string to_string(const zeek::spicy::rt::AnalyzerType& x, adl::tag );

}
