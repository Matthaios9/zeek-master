

#pragma once

#include <cassert>
#include <concepts>
#include <memory>
#include <type_traits>

#include "zeek/Expr.h"
#include "zeek/Frame.h"
#include "zeek/OpaqueVal.h"
#include "zeek/Reporter.h"

#include "broker/data.hh"

namespace zeek {


using BrokerTimespan = std::chrono::duration<int64_t, std::nano>;

class ODesc;

}

namespace zeek::Broker {

class Manager;

}

namespace zeek::threading {

struct Value;
struct Field;

}

namespace zeek::Broker::detail {

class StoreHandleVal;

extern OpaqueTypePtr opaque_of_data_type;
extern OpaqueTypePtr opaque_of_set_iterator;
extern OpaqueTypePtr opaque_of_table_iterator;
extern OpaqueTypePtr opaque_of_vector_iterator;
extern OpaqueTypePtr opaque_of_record_iterator;




TransportProto to_zeek_port_proto(broker::port::protocol tp);







RecordValPtr make_data_val(Val* v);






RecordValPtr make_data_val(broker::data d);







EnumValPtr get_data_type(RecordVal* v, zeek::detail::Frame* frame);







std::optional<broker::data> val_to_data(const Val* v, bool unwrap_broker_data = false);








ValPtr data_to_val(broker::data& d, Type* type);






broker::data threading_field_to_data(const threading::Field* f);







threading::Field* data_to_threading_field(const broker::data& d);




class DataVal : public OpaqueVal {
public:
    DataVal(broker::data arg_data) : OpaqueVal(opaque_of_data_type), data(std::move(arg_data)) {}

    void ValDescribe(ODesc* d) const override;

    ValPtr castTo(zeek::Type* t);
    bool canCastTo(zeek::Type* t) const;




    static const TypePtr& ScriptDataType();

    broker::data data;

protected:
    DataVal() : OpaqueVal(opaque_of_data_type) {}

    DECLARE_OPAQUE_VALUE_DATA(zeek::Broker::detail::DataVal)
};




struct type_name_getter {
    using result_type = const char*;

    result_type operator()(broker::none) { return "NONE"; }

    result_type operator()(bool) { return "bool"; }

    result_type operator()(uint64_t) { return "uint64_t"; }

    result_type operator()(int64_t) { return "int64_t"; }

    result_type operator()(double) { return "double"; }

    result_type operator()(const std::string&) { return "string"; }

    result_type operator()(const broker::address&) { return "address"; }

    result_type operator()(const broker::subnet&) { return "subnet"; }

    result_type operator()(const broker::port&) { return "port"; }

    result_type operator()(const broker::timestamp&) { return "time"; }

    result_type operator()(const broker::timespan&) { return "interval"; }

    result_type operator()(const broker::enum_value&) { return "enum"; }

    result_type operator()(const broker::set&) { return "set"; }

    result_type operator()(const broker::table&) { return "table"; }

    result_type operator()(const broker::vector&) {
        assert(tag == zeek::TYPE_VECTOR || tag == zeek::TYPE_RECORD);
        return tag == zeek::TYPE_VECTOR ? "vector" : "record";
    }

    zeek::TypeTag tag;
};








broker::data& opaque_field_to_data(zeek::RecordVal* v, zeek::detail::Frame* f);











template<typename T>
T& require_data_type(broker::data& d, zeek::TypeTag tag, zeek::detail::Frame* f) {
    auto ptr = broker::get_if<T>(&d);
    if ( ! ptr )
        zeek::reporter->RuntimeError(f->GetCallLocation(), "data is of type '%s' not of type '%s'",
                                     visit(type_name_getter{tag}, d), zeek::type_name(tag));

    return *ptr;
}




template<typename T>
inline T& require_data_type(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f) {
    return require_data_type<T>(opaque_field_to_data(v, f), tag, f);
}



class SetIterator : public zeek::OpaqueVal {
public:
    SetIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
        : zeek::OpaqueVal(opaque_of_set_iterator),
          dat(require_data_type<broker::set>(v, zeek::TYPE_TABLE, f)),
          it(dat.begin()) {}

    broker::set dat;
    broker::set::iterator it;

protected:
    SetIterator() : zeek::OpaqueVal(opaque_of_set_iterator) {}

    DECLARE_OPAQUE_VALUE_DATA(zeek::Broker::detail::SetIterator)
};

class TableIterator : public zeek::OpaqueVal {
public:
    TableIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
        : zeek::OpaqueVal(opaque_of_table_iterator),
          dat(require_data_type<broker::table>(v, zeek::TYPE_TABLE, f)),
          it(dat.begin()) {}

    broker::table dat;
    broker::table::iterator it;

protected:
    TableIterator() : zeek::OpaqueVal(opaque_of_table_iterator) {}

    DECLARE_OPAQUE_VALUE_DATA(zeek::Broker::detail::TableIterator)
};

class VectorIterator : public zeek::OpaqueVal {
public:
    VectorIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
        : zeek::OpaqueVal(opaque_of_vector_iterator),
          dat(require_data_type<broker::vector>(v, zeek::TYPE_VECTOR, f)),
          it(dat.begin()) {}

    broker::vector dat;
    broker::vector::iterator it;

protected:
    VectorIterator() : zeek::OpaqueVal(opaque_of_vector_iterator) {}

    DECLARE_OPAQUE_VALUE_DATA(zeek::Broker::detail::VectorIterator)
};

class RecordIterator : public zeek::OpaqueVal {
public:
    RecordIterator(zeek::RecordVal* v, zeek::TypeTag tag, zeek::detail::Frame* f)
        : zeek::OpaqueVal(opaque_of_record_iterator),
          dat(require_data_type<broker::vector>(v, zeek::TYPE_RECORD, f)),
          it(dat.begin()) {}

    broker::vector dat;
    broker::vector::iterator it;

protected:
    RecordIterator() : zeek::OpaqueVal(opaque_of_record_iterator) {}

    DECLARE_OPAQUE_VALUE_DATA(zeek::Broker::detail::RecordIterator)
};

}

namespace zeek {

class BrokerData;
class BrokerDataView;
class BrokerListView;

}

namespace zeek::detail {

class BrokerDataAccess;

}

namespace zeek {




class BrokerDataView {
public:
    friend class zeek::detail::BrokerDataAccess;
    friend class zeek::Broker::detail::DataVal;
    friend class zeek::Broker::detail::SetIterator;
    friend class zeek::Broker::detail::TableIterator;
    friend class zeek::Broker::detail::VectorIterator;
    friend class zeek::Broker::detail::RecordIterator;

    BrokerDataView() = delete;

    BrokerDataView(const BrokerDataView&) noexcept = default;

    explicit BrokerDataView(const broker::data* value) noexcept : value_(value) { assert(value != nullptr); }




    [[nodiscard]] bool IsNil() const noexcept { return broker::is<broker::none>(*value_); }




    [[nodiscard]] bool IsBool() const noexcept { return broker::is<bool>(*value_); }




    [[nodiscard]] bool ToBool(bool fallback = false) const noexcept {
        if ( auto val = broker::get_if<bool>(value_); val ) {
            return *val;
        }
        return fallback;
    }




    [[nodiscard]] bool IsString() const noexcept { return broker::is<std::string>(*value_); }




    [[nodiscard]] std::string_view ToString() const noexcept {
        if ( auto val = broker::get_if<std::string>(value_); val ) {
            return *val;
        }
        return std::string_view{};
    }




    [[nodiscard]] bool IsInteger() const noexcept { return broker::is<broker::integer>(*value_); }




    [[nodiscard]] int64_t ToInteger(int64_t fallback = 0) const noexcept {
        if ( auto val = broker::get_if<broker::integer>(value_); val ) {
            return *val;
        }
        return fallback;
    }




    [[nodiscard]] bool IsCount() const noexcept { return broker::is<broker::count>(*value_); }




    [[nodiscard]] uint64_t ToCount(uint64_t fallback = 0) const noexcept {
        if ( auto val = broker::get_if<broker::count>(value_); val ) {
            return *val;
        }
        return fallback;
    }




    [[nodiscard]] bool IsReal() const noexcept { return broker::is<broker::real>(*value_); }




    [[nodiscard]] double ToReal(double fallback = 0) const noexcept {
        if ( auto val = broker::get_if<broker::real>(value_); val ) {
            return *val;
        }
        return fallback;
    }




    [[nodiscard]] bool IsList() const noexcept { return broker::is<broker::vector>(*value_); }





    [[nodiscard]] BrokerListView ToList() noexcept;





    [[nodiscard]] ValPtr ToVal(Type* type);




    friend std::string to_string(const BrokerDataView& data) { return broker::to_string(*data.value_); }

private:
    const broker::data* value_;
};




template<std::same_as<BrokerDataView>... Args>
[[nodiscard]] bool are_all_counts(BrokerDataView arg, Args... args) {
    return arg.IsCount() && (args.IsCount() && ...);
}




template<std::same_as<BrokerDataView>... Args>
[[nodiscard]] auto to_count(BrokerDataView arg, Args... args) {
    return std::tuple{arg.ToCount(), args.ToCount()...};
}




class BrokerListView {
public:
    friend class zeek::detail::BrokerDataAccess;

    BrokerListView() = delete;

    BrokerListView(const BrokerListView&) noexcept = default;

    explicit BrokerListView(const broker::vector* values) noexcept : values_(values) { assert(values != nullptr); }





    [[nodiscard]] BrokerDataView Front() const { return BrokerDataView{std::addressof(values_->front())}; }





    [[nodiscard]] BrokerDataView Back() const { return BrokerDataView{std::addressof(values_->back())}; }





    [[nodiscard]] BrokerDataView operator[](size_t index) const {
        return BrokerDataView{std::addressof((*values_)[index])};
    }




    [[nodiscard]] size_t Size() const noexcept { return values_->size(); }




    [[nodiscard]] size_t IsEmpty() const noexcept { return values_->empty(); }

private:
    const broker::vector* values_;
};

class BrokerListBuilder;




class BrokerData {
public:
    friend class BrokerListBuilder;
    friend class zeek::Broker::Manager;
    friend class zeek::Broker::detail::StoreHandleVal;
    friend class zeek::detail::BrokerDataAccess;

    BrokerData() = default;


    template<std::same_as<broker::data> DataType>
    explicit BrokerData(DataType value) : value_(std::move(value)) {}

    BrokerDataView AsView() noexcept { return BrokerDataView{std::addressof(value_)}; }






    [[nodiscard]] bool Convert(const Val* value);




    [[nodiscard]] bool Convert(const ValPtr& value) { return Convert(value.get()); }




    [[nodiscard]] RecordValPtr ToRecordVal() &&;





    [[nodiscard]] static RecordValPtr ToRecordVal(const Val* value);




    [[nodiscard]] static RecordValPtr ToRecordVal(const ValPtr& value) { return ToRecordVal(value.get()); }




    [[nodiscard]] static BrokerData FromString(const char* cstr, size_t len) {
        return BrokerData{broker::data{std::string{cstr, len}}};
    }




    friend std::string to_string(const BrokerData& data) { return broker::to_string(data.value_); }

private:
    broker::data value_;
};




class BrokerListBuilder {
public:
    friend class zeek::Broker::Manager;




    void Reserve(size_t n) { values_.reserve(n); }




    [[nodiscard]] bool Add(const Val* value);




    [[nodiscard]] bool Add(const ValPtr& value) { return Add(value.get()); }




    template<typename T>
    void AddCount(T value) {
        if constexpr ( std::is_enum_v<T> ) {
            AddCount(static_cast<std::underlying_type_t<T>>(value));
        }
        else {
            static_assert(std::is_integral_v<T> && ! std::is_same_v<bool, T>);
            static_assert(std::is_unsigned_v<T>);
            static_assert(sizeof(T) <= sizeof(broker::count));
            values_.emplace_back(static_cast<broker::count>(value));
        }
    }




    template<typename T>
    void AddInteger(T value) {
        if constexpr ( std::is_enum_v<T> ) {
            AddInteger(static_cast<std::underlying_type_t<T>>(value));
        }
        else {
            static_assert(std::is_integral_v<T> && ! std::is_same_v<bool, T>);
            static_assert(std::is_signed_v<T>);
            static_assert(sizeof(T) <= sizeof(broker::integer));
            values_.emplace_back(static_cast<broker::integer>(value));
        }
    }




    void Add(uint64_t value) { values_.emplace_back(static_cast<broker::count>(value)); }




    void Add(int64_t value) { values_.emplace_back(static_cast<broker::integer>(value)); }




    void Add(double value) { values_.emplace_back(value); }




    void Add(bool value) { values_.emplace_back(value); }




    void Add(std::string value) { values_.emplace_back(std::move(value)); }






    void Add(const char* cstr, size_t len) { values_.emplace_back(std::string{cstr, len}); }




    void Add(BrokerData value) { values_.emplace_back(std::move(value.value_)); }




    void Add(BrokerListBuilder&& builder) { values_.emplace_back(std::move(builder.values_)); }




    void AddNil() { values_.emplace_back(); }




    template<class... Ts>
    void AddList(Ts&&... values) {
        BrokerListBuilder sub;
        (sub.Add(std::forward<Ts>(values)), ...);
        values_.emplace_back(std::move(sub.values_));
    }




    BrokerData Build() && { return BrokerData{broker::data{std::move(values_)}}; }

private:
    broker::vector values_;
};

}

namespace zeek::detail {

class BrokerDataAccess {
public:
    static broker::data& Unbox(BrokerData& data) { return data.value_; }

    static const broker::data& Unbox(const BrokerData& data) { return data.value_; }

    static broker::data&& Unbox(BrokerData&& data) { return std::move(data.value_); }

    static const broker::data& Unbox(const BrokerDataView& data) { return *data.value_; }
};

}
