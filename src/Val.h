

#pragma once

#include <sys/types.h>
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/Notifier.h"
#include "zeek/Reporter.h"
#include "zeek/Timer.h"
#include "zeek/Type.h"
#include "zeek/ZVal.h"
#include "zeek/net_util.h"




constexpr int NUM_PORT_SPACES = 4;
constexpr uint32_t PORT_SPACE_MASK = 0x30000;

constexpr uint32_t TCP_PORT_MASK = 0x10000;
constexpr uint32_t UDP_PORT_MASK = 0x20000;
constexpr uint32_t ICMP_PORT_MASK = 0x30000;

namespace zeek {

class String;
class Func;
class IPAddr;
class IPPrefix;
class RE_Matcher;
class File;
using FilePtr = zeek::IntrusivePtr<File>;

template<typename T>
class RobustDictIterator;
template<typename T>
class Dictionary;
template<typename T>
using PDict = Dictionary<T>;

namespace detail {

class ScriptFunc;
class Frame;
class PrefixTable;
class HashKey;
class TablePatternMatcher;

struct DFA_State_Cache_Stats;

class ValTrace;
class ZBody;
class CPPRuntime;


class PublishOnChangeState;

}

namespace logging {
class Manager;
}

}

#include "zeek/RunState.h"

namespace zeek {

using FuncPtr = IntrusivePtr<Func>;
using FilePtr = IntrusivePtr<File>;

class Val;
class PortVal;
class AddrVal;
class SubNetVal;
class IntervalVal;
class FuncVal;
class FileVal;
class PatternVal;
class TableVal;
class RecordVal;
class ListVal;
class StringVal;
class EnumVal;
class OpaqueVal;
class VectorVal;
class TableEntryVal;
class TypeVal;

using AddrValPtr = IntrusivePtr<AddrVal>;
using EnumValPtr = IntrusivePtr<EnumVal>;
using FuncValPtr = IntrusivePtr<FuncVal>;
using ListValPtr = IntrusivePtr<ListVal>;
using PortValPtr = IntrusivePtr<PortVal>;
using RecordValPtr = IntrusivePtr<RecordVal>;
using StringValPtr = IntrusivePtr<StringVal>;
using TableValPtr = IntrusivePtr<TableVal>;
using ValPtr = IntrusivePtr<Val>;
using VectorValPtr = IntrusivePtr<VectorVal>;

class Val : public Obj {
public:
    static inline const ValPtr nil;

    ~Val() override;

    Val* Ref() {
        zeek::Ref(this);
        return this;
    }
    ValPtr Clone();

    bool IsZero() const;
    bool IsOne() const;

    zeek_int_t InternalInt() const;
    zeek_uint_t InternalUnsigned() const;
    double InternalDouble() const;

    zeek_int_t CoerceToInt() const;
    zeek_uint_t CoerceToUnsigned() const;
    double CoerceToDouble() const;



    virtual ValPtr SizeVal() const;









    unsigned int Footprint() const {
        std::unordered_set<const Val*> analyzed_vals;
        return Footprint(&analyzed_vals);
    }





    virtual bool AddTo(Val* v, bool is_first_init) const;


    virtual bool RemoveFrom(Val* v) const;

    const TypePtr& GetType() const { return type; }

    template<class T>
    IntrusivePtr<T> GetType() const {
        return cast_intrusive<T>(type);
    }


#define UNDERLYING_ACCESSOR_DECL(ztype, ctype, name) ctype name() const;

    UNDERLYING_ACCESSOR_DECL(detail::IntValImplementation, zeek_int_t, AsInt)
    UNDERLYING_ACCESSOR_DECL(BoolVal, bool, AsBool)
    UNDERLYING_ACCESSOR_DECL(EnumVal, zeek_int_t, AsEnum)
    UNDERLYING_ACCESSOR_DECL(detail::UnsignedValImplementation, zeek_uint_t, AsCount)
    UNDERLYING_ACCESSOR_DECL(detail::DoubleValImplementation, double, AsDouble)
    UNDERLYING_ACCESSOR_DECL(TimeVal, double, AsTime)
    UNDERLYING_ACCESSOR_DECL(IntervalVal, double, AsInterval)
    UNDERLYING_ACCESSOR_DECL(AddrVal, const IPAddr&, AsAddr)
    UNDERLYING_ACCESSOR_DECL(SubNetVal, const IPPrefix&, AsSubNet)
    UNDERLYING_ACCESSOR_DECL(StringVal, const String*, AsString)
    UNDERLYING_ACCESSOR_DECL(FuncVal, Func*, AsFunc)
    UNDERLYING_ACCESSOR_DECL(FileVal, File*, AsFile)
    UNDERLYING_ACCESSOR_DECL(PatternVal, const RE_Matcher*, AsPattern)
    UNDERLYING_ACCESSOR_DECL(TableVal, const PDict<TableEntryVal>*, AsTable)
    UNDERLYING_ACCESSOR_DECL(TypeVal, zeek::Type*, AsType)

    FuncVal* AsFuncVal();
    const FuncVal* AsFuncVal() const;

    FileVal* AsFileVal();
    const FileVal* AsFileVal() const;

    PatternVal* AsPatternVal();
    const PatternVal* AsPatternVal() const;

    PortVal* AsPortVal();
    const PortVal* AsPortVal() const;

    SubNetVal* AsSubNetVal();
    const SubNetVal* AsSubNetVal() const;

    AddrVal* AsAddrVal();
    const AddrVal* AsAddrVal() const;

    TableVal* AsTableVal();
    const TableVal* AsTableVal() const;

    RecordVal* AsRecordVal();
    const RecordVal* AsRecordVal() const;

    ListVal* AsListVal();
    const ListVal* AsListVal() const;

    StringVal* AsStringVal();
    const StringVal* AsStringVal() const;

    VectorVal* AsVectorVal();
    const VectorVal* AsVectorVal() const;

    EnumVal* AsEnumVal();
    const EnumVal* AsEnumVal() const;

    OpaqueVal* AsOpaqueVal();
    const OpaqueVal* AsOpaqueVal() const;

    TypeVal* AsTypeVal();
    const TypeVal* AsTypeVal() const;

    void Describe(ODesc* d) const override;
    virtual void DescribeReST(ODesc* d) const;



    virtual notifier::detail::Modifiable* Modifiable() { return nullptr; }

    TableValPtr GetRecordFields();


















    StringValPtr ToJSON(bool only_loggable = false, RE_Matcher* re = nullptr, bool interval_as_double = false);

    template<typename T>
        requires std::is_pointer_v<T>
    T As() {
        return static_cast<T>(this);
    }

protected:

    friend class EnumType;
    friend class ListVal;
    friend class RecordVal;
    friend class TableVal;
    friend class VectorVal;
    friend class ValManager;
    friend class TableEntryVal;

    virtual void ValDescribe(ODesc* d) const;
    virtual void ValDescribeReST(ODesc* d) const;

    static ValPtr MakeBool(bool b);
    static ValPtr MakeInt(zeek_int_t i);
    static ValPtr MakeCount(zeek_uint_t u);

    explicit Val(TypePtr t) noexcept : type(std::move(t)) {}










    unsigned int Footprint(std::unordered_set<const Val*>* analyzed_vals) const;
    virtual unsigned int ComputeFootprint(std::unordered_set<const Val*>* analyzed_vals) const { return 1; }


    struct CloneState {



        ValPtr NewClone(Val* src, ValPtr dst);

        std::unordered_map<Val*, Val*> clones;
    };

    ValPtr Clone(CloneState* state);
    virtual ValPtr DoClone(CloneState* state);

    TypePtr type;
};



class ValManager {
public:
    static constexpr zeek_uint_t PREALLOCATED_COUNTS = 4096;
    static constexpr zeek_uint_t PREALLOCATED_INTS = 512;
    static constexpr zeek_int_t PREALLOCATED_INT_LOWEST = -255;
    static constexpr zeek_int_t PREALLOCATED_INT_HIGHEST = PREALLOCATED_INT_LOWEST + PREALLOCATED_INTS - 1;

    ValManager();

    inline const ValPtr& True() const { return b_true; }

    inline const ValPtr& False() const { return b_false; }

    inline const ValPtr& Bool(bool b) const { return b ? b_true : b_false; }

    inline ValPtr Int(int64_t i) const {
        return i < PREALLOCATED_INT_LOWEST || i > PREALLOCATED_INT_HIGHEST ? Val::MakeInt(i) :
                                                                             ints[i - PREALLOCATED_INT_LOWEST];
    }

    inline ValPtr Count(uint64_t i) const { return i >= PREALLOCATED_COUNTS ? Val::MakeCount(i) : counts[i]; }

    inline const StringValPtr& EmptyString() const { return empty_string; }


    const PortValPtr& Port(uint32_t port_num, TransportProto port_type);


    const PortValPtr& Port(uint32_t port_num);

private:
#ifdef PREALLOCATE_PORT_ARRAY
    std::array<std::array<PortValPtr, 65536>, NUM_PORT_SPACES> ports;
#else
    std::unordered_map<uint32_t, PortValPtr> ports;
#endif

    std::array<ValPtr, PREALLOCATED_COUNTS> counts;
    std::array<ValPtr, PREALLOCATED_INTS> ints;
    StringValPtr empty_string;
    ValPtr b_true;
    ValPtr b_false;
};

ZEEK_EXTERN_DATA ValManager* val_mgr;

namespace detail {





class IntValImplementation : public Val {
public:
    IntValImplementation(TypePtr t, zeek_int_t v) : Val(std::move(t)), int_val(v) {}

    zeek_int_t Get() const { return int_val; }

protected:
    zeek_int_t int_val;
};

class UnsignedValImplementation : public Val {
public:
    UnsignedValImplementation(TypePtr t, zeek_uint_t v) : Val(std::move(t)), uint_val(v) {}

    zeek_uint_t Get() const { return uint_val; }

protected:
    zeek_uint_t uint_val;
};

class DoubleValImplementation : public Val {
public:
    DoubleValImplementation(TypePtr t, double v) : Val(std::move(t)), double_val(v) {}

    double Get() const { return double_val; }

protected:
    double double_val;
};

}

class IntVal final : public detail::IntValImplementation {
public:
    IntVal(zeek_int_t v) : detail::IntValImplementation(base_type(TYPE_INT), v) {}



};

class BoolVal final : public detail::IntValImplementation {
public:
    BoolVal(zeek_int_t v) : detail::IntValImplementation(base_type(TYPE_BOOL), v) {}


    bool Get() const { return static_cast<bool>(int_val); }
};

class CountVal : public detail::UnsignedValImplementation {
public:
    CountVal(zeek_uint_t v) : detail::UnsignedValImplementation(base_type(TYPE_COUNT), v) {}


};

class DoubleVal : public detail::DoubleValImplementation {
public:
    DoubleVal(double v) : detail::DoubleValImplementation(base_type(TYPE_DOUBLE), v) {}


};

constexpr double Microseconds = 1e-6;
constexpr double Milliseconds = 1e-3;
constexpr double Seconds = 1.0;
constexpr double Minutes = (60 * Seconds);
constexpr double Hours = (60 * Minutes);
constexpr double Days = (24 * Hours);

class IntervalVal final : public detail::DoubleValImplementation {
public:
    IntervalVal(double quantity, double units = Seconds)
        : detail::DoubleValImplementation(base_type(TYPE_INTERVAL), quantity * units) {}



protected:
    void ValDescribe(ODesc* d) const override;
};

class TimeVal final : public detail::DoubleValImplementation {
public:
    TimeVal(double t) : detail::DoubleValImplementation(base_type(TYPE_TIME), t) {}


};

class PortVal final : public detail::UnsignedValImplementation {
public:
    ValPtr SizeVal() const override;


    uint32_t Port() const;
    std::string Protocol() const;


    bool IsTCP() const;
    bool IsUDP() const;
    bool IsICMP() const;

    TransportProto PortType() const {
        if ( IsTCP() )
            return TRANSPORT_TCP;
        else if ( IsUDP() )
            return TRANSPORT_UDP;
        else if ( IsICMP() )
            return TRANSPORT_ICMP;
        else
            return TRANSPORT_UNKNOWN;
    }


    static uint32_t Mask(uint32_t port_num, TransportProto port_type);



    PortVal(uint32_t p);

protected:
    void ValDescribe(ODesc* d) const override;
    ValPtr DoClone(CloneState* state) override;

private:



    friend class RecordVal;
    PortValPtr Get() { return {NewRef{}, this}; }
};

class AddrVal final : public Val {
public:
    explicit AddrVal(const char* text);
    explicit AddrVal(const std::string& text);
    ~AddrVal() override;

    ValPtr SizeVal() const override;


    explicit AddrVal(uint32_t addr);
    explicit AddrVal(const uint32_t addr[4]);
    explicit AddrVal(const IPAddr& addr);

    const IPAddr& Get() const { return *addr_val; }

protected:
    ValPtr DoClone(CloneState* state) override;

private:
    IPAddr* addr_val;
};

class SubNetVal final : public Val {
public:
    explicit SubNetVal(const char* text);
    SubNetVal(const char* text, int width);
    SubNetVal(uint32_t addr, int width);
    SubNetVal(const uint32_t addr[4], int width);
    SubNetVal(const IPAddr& addr, int width);
    explicit SubNetVal(const IPPrefix& prefix);
    ~SubNetVal() override;

    ValPtr SizeVal() const override;

    const IPAddr& Prefix() const;
    int Width() const;
    IPAddr Mask() const;

    bool Contains(const IPAddr& addr) const;

    const IPPrefix& Get() const { return *subnet_val; }

protected:
    void ValDescribe(ODesc* d) const override;
    ValPtr DoClone(CloneState* state) override;

private:
    IPPrefix* subnet_val;
};

class StringVal final : public Val {
public:
    explicit StringVal(String* s);
    StringVal(std::string_view s);
    StringVal(int length, const char* s);
    ~StringVal() override;

    ValPtr SizeVal() const override;

    int Len() const;
    const u_char* Bytes() const;
    const char* CheckString() const;
    std::pair<const char*, size_t> CheckStringWithSize() const;






    std::string ToStdString() const;
    std::string_view ToStdStringView() const;
    StringVal* ToUpper();

    const String* Get() const { return string_val; }

    StringValPtr Replace(RE_Matcher* re, const String& repl, bool do_all);

protected:
    unsigned int ComputeFootprint(std::unordered_set<const Val*>* analyzed_vals) const override;

    void ValDescribe(ODesc* d) const override;
    ValPtr DoClone(CloneState* state) override;

private:
    String* string_val;
};

class FuncVal final : public Val {
public:
    explicit FuncVal(FuncPtr f);

    FuncPtr AsFuncPtr() const;

    ValPtr SizeVal() const override;

    Func* Get() const { return func_val.get(); }

protected:
    void ValDescribe(ODesc* d) const override;
    ValPtr DoClone(CloneState* state) override;

private:
    FuncPtr func_val;
};

class FileVal final : public Val {
public:
    explicit FileVal(FilePtr f);

    FilePtr AsFilePtr() const;

    ValPtr SizeVal() const override;

    File* Get() const { return file_val.get(); }

protected:
    void ValDescribe(ODesc* d) const override;
    ValPtr DoClone(CloneState* state) override;

private:
    FilePtr file_val;
};

class PatternVal final : public Val {
public:
    explicit PatternVal(RE_Matcher* re);
    ~PatternVal() override;

    bool AddTo(Val* v, bool is_first_init) const override;

    void SetMatcher(RE_Matcher* re);

    bool MatchExactly(const String* s) const;
    bool MatchAnywhere(const String* s) const;

    const RE_Matcher* Get() const { return re_val; }

protected:
    void ValDescribe(ODesc* d) const override;
    ValPtr DoClone(CloneState* state) override;

private:
    RE_Matcher* re_val;
};



class ListVal final : public Val {
public:



    explicit ListVal(TypeTag t) : ListVal(base_type(t)) {}




    explicit ListVal(TypePtr t);



    ListVal(TypeListPtr tl, std::vector<ValPtr> vals);

    TypeTag BaseTag() const { return tag; }

    ValPtr SizeVal() const override;

    int Length() const { return vals.size(); }

    const ValPtr& Idx(size_t i) const { return vals[i]; }









    RE_Matcher* BuildRE() const;





    void Append(ValPtr v);




    void Clear() {
        vals.clear();
        type->AsTypeList()->Clear();
    }


    TableValPtr ToSetVal() const;

    const std::vector<ValPtr>& Vals() const { return vals; }

    void Describe(ODesc* d) const override;

protected:
    unsigned int ComputeFootprint(std::unordered_set<const Val*>* analyzed_vals) const override;

    ValPtr DoClone(CloneState* state) override;

    std::vector<ValPtr> vals;
    TypeTag tag;
};

class TableEntryVal {
public:
    explicit TableEntryVal(ValPtr v) : val(std::move(v)) {
        expire_access_time = static_cast<int>(run_state::network_time - run_state::zeek_start_network_time);
    }

    TableEntryVal* Clone(Val::CloneState* state);

    const ValPtr& GetVal() const { return val; }


    double ExpireAccessTime() const { return run_state::zeek_start_network_time + expire_access_time; }
    void SetExpireAccess(double time) {
        expire_access_time = static_cast<int>(time - run_state::zeek_start_network_time);
    }

protected:
    friend class TableVal;

    ValPtr val;




    int expire_access_time;
};

class TableValTimer final : public detail::Timer {
public:
    TableValTimer(TableVal* val, double t);
    ~TableValTimer() override;

    void Dispatch(double t, bool is_expire) override;

    TableVal* Table() { return table; }

protected:
    TableVal* table;
};

class TableVal final : public Val, public notifier::detail::Modifiable {
public:
    explicit TableVal(TableTypePtr t, detail::AttributesPtr attrs = nullptr);

    ~TableVal() override;













    bool Assign(ValPtr index, ValPtr new_val, bool broker_forward = true, bool* iterators_invalidated = nullptr);















    bool Assign(ValPtr index, std::unique_ptr<detail::HashKey> k, ValPtr new_val, bool broker_forward = true,
                bool* iterators_invalidated = nullptr);

    ValPtr SizeVal() const override;






    bool AddTo(Val* v, bool is_first_init) const override;


    bool AddTo(Val* v, bool is_first_init, bool propagate_ops) const;


    void RemoveAll();




    bool RemoveFrom(Val* v) const override;









    TableValPtr Intersection(const TableVal& v) const;








    TableValPtr Union(TableVal* v) const {
        auto v_clone = cast_intrusive<TableVal>(v->Clone());
        AddTo(v_clone.get(), false, false);
        return v_clone;
    }






    TableValPtr TakeOut(TableVal* v) {
        auto clone = cast_intrusive<TableVal>(Clone());
        v->RemoveFrom(clone.get());
        return clone;
    }





    bool EqualTo(const TableVal& v) const;
    bool EqualTo(const TableValPtr& v) const { return EqualTo(*(v.get())); }



    bool IsSubsetOf(const TableVal& v) const;










    const ValPtr& Find(const ValPtr& index);











    ValPtr FindOrDefault(const ValPtr& index);









    bool Contains(const IPAddr& addr) const;




    VectorValPtr LookupSubnets(const SubNetVal* s);




    TableValPtr LookupSubnetValues(const SubNetVal* s);




    VectorValPtr LookupPattern(const StringValPtr& s);




    VectorValPtr LookupPattern(std::string_view sv);




    bool MatchPattern(const StringValPtr& s);



    void GetPatternMatcherStats(detail::DFA_State_Cache_Stats* stats) const;



    bool UpdateTimestamp(Val* index);




    ListValPtr RecreateIndex(const detail::HashKey& k) const;













    ValPtr Remove(const Val& index, bool broker_forward = true, bool* iterators_invalidated = nullptr);








    ValPtr Remove(const detail::HashKey& k, bool* iterators_invalidated = nullptr);


    [[deprecated("Remove in v9.1. Pass a TypePtr instead, using Type::nil for TYPE_ANY")]]
    ListValPtr ToListVal(TypeTag t) const;


    ListValPtr ToListVal(TypePtr t = nullptr) const;



    ListValPtr ToPureListVal() const;


    std::unordered_map<ValPtr, ValPtr> ToMap() const;

    void SetAttrs(detail::AttributesPtr attrs);

    const detail::AttrPtr& GetAttr(detail::AttrTag t) const;

    const detail::AttributesPtr& GetAttrs() const { return attrs; }

    const PDict<TableEntryVal>* Get() const { return table_val; }

    const detail::CompositeHash* GetTableHash() const { return table_type->GetTableHash(); }


    int Size() const;
    int RecursiveSize() const;




    const detail::PrefixTable* Subnets() const { return subnets.get(); }


    void Describe(ODesc* d) const override;

    void InitTimer(double delay);
    void DoExpire(double t);




    void InitDefaultFunc(detail::Frame* f);



    void InitDefaultVal(ValPtr def_val);

    void ClearTimer(detail::Timer* t) {
        if ( timer == t )
            timer = nullptr;
    }






    std::unique_ptr<detail::HashKey> MakeHashKey(const Val& index) const;

    notifier::detail::Modifiable* Modifiable() override { return this; }



    static void SaveParseTimeTableState(RecordType* rt);




    static void RebuildParseTimeTables();



    static void DoneParsing();





    void SetBrokerStore(const std::string& store) { broker_store = store; }




    void DisableChangeNotifications() { in_change_func = true; }




    void EnableChangeNotifications() { in_change_func = false; }




    detail::PublishOnChangeState* GetPublishOnChangeState() const { return poc_state.get(); }




    void SetPublishOnChangeState(std::unique_ptr<detail::PublishOnChangeState> poc_state_arg);

protected:
    void Init(TableTypePtr t, bool ordered = false);

    using TableRecordDependencies = std::unordered_map<RecordType*, std::vector<TableValPtr>>;

    using ParseTimeTableState = std::vector<std::pair<ValPtr, ValPtr>>;
    using ParseTimeTableStates = std::unordered_map<TableVal*, ParseTimeTableState>;

    ParseTimeTableState DumpTableState();
    void RebuildTable(ParseTimeTableState ptts);

    void CheckExpireAttr(detail::AttrTag at);


    ValPtr Default(const ValPtr& index);


    const detail::AttrPtr& DefaultAttr() const;


    bool ExpirationEnabled() { return expire_time != nullptr; }




    double GetExpireTime();


    double CallExpireFunc(ListValPtr idx);


    enum OnChangeType : uint8_t { ELEMENT_NEW, ELEMENT_CHANGED, ELEMENT_REMOVED, ELEMENT_EXPIRED };


    void CallChangeFunc(const ValPtr& index, const ValPtr& old_value, OnChangeType type);


    void SendToStore(const Val* index, const TableEntryVal* new_entry_val, OnChangeType type);

    unsigned int ComputeFootprint(std::unordered_set<const Val*>* analyzed_vals) const override;

    ValPtr DoClone(CloneState* state) override;

    TableTypePtr table_type;
    detail::AttributesPtr attrs;
    detail::ExprPtr expire_time;
    detail::ExprPtr expire_func;
    TableValTimer* timer;
    RobustDictIterator<TableEntryVal>* expire_iterator;
    std::unique_ptr<detail::PrefixTable> subnets;
    std::unique_ptr<detail::TablePatternMatcher> pattern_matcher;
    ValPtr def_val;
    detail::ExprPtr change_func;
    std::string broker_store;




    std::unique_ptr<detail::PublishOnChangeState> poc_state;


    bool in_change_func = false;

    static TableRecordDependencies parse_time_table_record_dependencies;
    static ParseTimeTableStates parse_time_table_states;

private:
    PDict<TableEntryVal>* table_val;
};






template<typename T>
struct is_zeek_val {
    static constexpr bool value = std::disjunction_v<
        std::is_same<AddrVal, T>, std::is_same<BoolVal, T>, std::is_same<CountVal, T>, std::is_same<DoubleVal, T>,
        std::is_same<EnumVal, T>, std::is_same<FileVal, T>, std::is_same<FuncVal, T>, std::is_same<IntVal, T>,
        std::is_same<IntervalVal, T>, std::is_same<ListVal, T>, std::is_same<OpaqueVal, T>, std::is_same<PatternVal, T>,
        std::is_same<PortVal, T>, std::is_same<RecordVal, T>, std::is_same<StringVal, T>, std::is_same<SubNetVal, T>,
        std::is_same<TableVal, T>, std::is_same<TimeVal, T>, std::is_same<TypeVal, T>, std::is_same<VectorVal, T>>;
};
template<typename T>
inline constexpr bool is_zeek_val_v = is_zeek_val<T>::value;




















class ZValElement {
public:



    ZValElement() = default;










    ZValElement(ValPtr v, const TypePtr& t)
        : is_set(true), is_managed(ZVal::IsManagedType(t)), tag(t->Tag()), zval(v, t) {}









    ZValElement(const TypePtr& t) : is_managed(ZVal::IsManagedType(t)), tag(t->Tag()) {}




    ZValElement(const ZValElement& o) : is_set(o.is_set), is_managed(o.is_managed), tag(o.tag), zval(o.zval) {
        if ( is_set && is_managed )
            Ref(zval.ManagedVal());
    }




    ~ZValElement() { Reset(); }





    ZValElement& operator=(const ZValElement& o) {
        if ( this == &o )
            return *this;

        if ( is_set && is_managed )
            Unref(zval.ManagedVal());

        is_set = o.is_set;
        is_managed = o.is_managed;
        tag = o.tag;
        zval = o.zval;

        if ( is_set && is_managed )
            Ref(zval.ManagedVal());

        return *this;
    }






    ZValElement& operator=(ZValElement&& o) noexcept {
        if ( this == &o )
            return *this;

        if ( is_set && is_managed )
            Unref(zval.ManagedVal());

        is_set = o.is_set;
        is_managed = o.is_managed;
        tag = o.tag;
        zval = o.zval;


        o.is_set = false;
        o.zval = ZVal();

        return *this;
    }











    ZValElement& operator=(const ZVal& zv) {
        if ( is_set && is_managed )
            Unref(zval.ManagedVal());

        is_set = true;
        zval = zv;

        return *this;
    }







    const ZValElement& operator=(const TypeDecl& td) noexcept {
        assert(! IsSet());
        assert(tag == TYPE_ERROR);
        is_managed = td.is_managed;
        tag = td.tag;
        return *this;
    }


    operator bool() const noexcept { return is_set; }
    const ZVal* operator->() const noexcept { return &zval; }
    ZVal& operator*() noexcept { return zval; }
    const ZVal& operator*() const noexcept { return zval; }

    bool IsSet() const noexcept { return is_set; }
    bool IsManaged() const noexcept { return is_managed; }
    TypeTag Tag() const noexcept { return tag; }







    void Reset() {
        if ( is_set && is_managed )
            Unref(zval.ManagedVal());

        is_set = false;
    }









    ValPtr ToVal(const TypePtr& t) {
        assert(IsSet());
        return zval.ToVal(t);
    }

private:
    bool is_set = false;
    bool is_managed = false;
    TypeTag tag = TYPE_ERROR;

    ZVal zval;
};

static_assert(sizeof(ZValElement) <= 16);

class RecordVal final : public Val, public notifier::detail::Modifiable {
public:
    explicit RecordVal(RecordTypePtr t, bool init_fields = true);

    ~RecordVal() override;

    ValPtr SizeVal() const override;






    void Assign(int field, ValPtr new_val);








    template<class T, class... Ts>
        requires std::is_constructible_v<T, Ts...>
    void Assign(int field, Ts&&... args) {
        Assign(field, make_intrusive<T>(std::forward<Ts>(args)...));
    }






    void Remove(int field);


    void Assign(int field, bool new_val) {
        record_val[field] = ZVal(static_cast<zeek_int_t>(new_val));
        AddedField(field);
    }



    void Assign(int field, int32_t new_val) {
        record_val[field] = ZVal(static_cast<zeek_int_t>(new_val));
        AddedField(field);
    }
    void Assign(int field, int64_t new_val) {
        record_val[field] = ZVal(static_cast<zeek_int_t>(new_val));
        AddedField(field);
    }
    void Assign(int field, uint32_t new_val) {
        record_val[field] = ZVal(static_cast<zeek_uint_t>(new_val));
        AddedField(field);
    }
    void Assign(int field, uint64_t new_val) {
        record_val[field] = ZVal(static_cast<zeek_uint_t>(new_val));
        AddedField(field);
    }

    void Assign(int field, double new_val) {
        record_val[field] = ZVal(new_val);
        AddedField(field);
    }





    void AssignTime(int field, double new_val) { Assign(field, new_val); }
    void AssignInterval(int field, double new_val) { Assign(field, new_val); }

    void Assign(int field, StringVal* new_val) {
        record_val[field] = ZVal(new_val);
        AddedField(field);
    }
    void Assign(int field, const char* new_val) { Assign(field, new StringVal(new_val)); }
    void Assign(int field, const std::string& new_val) { Assign(field, new StringVal(new_val)); }
    void Assign(int field, std::string_view new_val) { Assign(field, new StringVal(new_val)); }
    void Assign(int field, String* new_val) { Assign(field, new StringVal(new_val)); }





    template<class T>
    void AssignField(const char* field_name, T&& val) {
        int idx = GetRecordType()->FieldOffset(field_name);
        if ( idx < 0 )
            reporter->InternalError("missing record field: %s", field_name);
        Assign(idx, std::forward<T>(val));
    }





    unsigned int NumFields() const { return num_fields; }







    bool HasField(int field) const {
        if ( record_val[field] )
            return true;

        return GetRecordType()->DeferredInits()[field] != nullptr;
    }







    bool HasField(const char* field) const {
        int idx = GetRecordType()->FieldOffset(field);
        return (idx != -1) && HasField(idx);
    }






    ValPtr GetField(int field) const {
        const auto* rt = GetRecordType();
        auto& fv = record_val[field];
        if ( ! fv ) {
            const auto& fi = rt->DeferredInits()[field];
            if ( ! fi )
                return nullptr;

            fv = fi->Generate();
        }

        return fv.ToVal(rt->GetFieldType(field));
    }






    template<class T>
    IntrusivePtr<T> GetField(int field) const {
        return cast_intrusive<T>(GetField(field));
    }









    ValPtr GetFieldOrDefault(int field) const;







    ValPtr GetField(const char* field) const;







    template<class T>
    IntrusivePtr<T> GetField(const char* field) const {
        return cast_intrusive<T>(GetField(field));
    }










    ValPtr GetFieldOrDefault(const char* field) const;








    template<class T>
    IntrusivePtr<T> GetFieldOrDefault(const char* field) const {
        return cast_intrusive<T>(GetField(field));
    }



    bool HasRawField(int field) const { return record_val[field].IsSet(); }






    template<typename T>
        requires is_zeek_val_v<T>
    auto GetFieldAs(int field) const -> std::invoke_result_t<decltype(&T::Get), T> {
        if constexpr ( std::is_same_v<T, BoolVal> || std::is_same_v<T, IntVal> || std::is_same_v<T, EnumVal> )
            return record_val[field]->int_val;
        else if constexpr ( std::is_same_v<T, CountVal> )
            return record_val[field]->uint_val;
        else if constexpr ( std::is_same_v<T, DoubleVal> || std::is_same_v<T, TimeVal> ||
                            std::is_same_v<T, IntervalVal> )
            return record_val[field]->double_val;
        else if constexpr ( std::is_same_v<T, PortVal> )
            return val_mgr->Port(record_val[field]->uint_val);
        else if constexpr ( std::is_same_v<T, StringVal> )
            return record_val[field]->string_val->Get();
        else if constexpr ( std::is_same_v<T, AddrVal> )
            return record_val[field]->addr_val->Get();
        else if constexpr ( std::is_same_v<T, SubNetVal> )
            return record_val[field]->subnet_val->Get();
        else if constexpr ( std::is_same_v<T, File> )
            return *(record_val[field]->file_val);
        else if constexpr ( std::is_same_v<T, Func> )
            return *(record_val[field]->func_val);
        else if constexpr ( std::is_same_v<T, PatternVal> )
            return record_val[field]->re_val->Get();
        else if constexpr ( std::is_same_v<T, RecordVal> )
            return record_val[field]->record_val;
        else if constexpr ( std::is_same_v<T, VectorVal> )
            return record_val[field]->vector_val;
        else if constexpr ( std::is_same_v<T, TableVal> )
            return record_val[field]->table_val->Get();
        else {



            reporter->InternalError("bad type in GetFieldAs");
        }
    }

    template<typename T>
        requires(! is_zeek_val_v<T>)
    T GetFieldAs(int field) const {
        if constexpr ( std::is_integral_v<T> && std::is_signed_v<T> )
            return record_val[field]->int_val;
        else if constexpr ( std::is_integral_v<T> && std::is_unsigned_v<T> )
            return record_val[field]->uint_val;
        else if constexpr ( std::is_floating_point_v<T> )
            return record_val[field]->double_val;




        return T{};
    }

    template<typename T>
    auto GetFieldAs(const char* field) const {
        int idx = GetRecordType()->FieldOffset(field);

        if ( idx < 0 )
            reporter->InternalError("missing record field: %s", field);

        return GetFieldAs<T>(idx);
    }

    void Describe(ODesc* d) const override;




    TableValPtr GetRecordFieldsVal() const;



    void SetOrigin(Obj* o) { origin = o; }
    Obj* GetOrigin() const { return origin; }








    RecordValPtr CoerceTo(RecordTypePtr other, bool allow_orphaning = false) const {
        return DoCoerceTo(std::move(other), allow_orphaning);
    }
    RecordValPtr CoerceTo(RecordTypePtr other, bool allow_orphaning = false);

    void DescribeReST(ODesc* d) const override;

    notifier::detail::Modifiable* Modifiable() override { return this; }




    static void ResizeParseTimeRecords(RecordType* rt);

    static void DoneParsing();

protected:
    friend class zeek::logging::Manager;
    friend class zeek::detail::ValTrace;
    friend class zeek::detail::ZBody;
    friend class zeek::detail::CPPRuntime;
    friend class zeek::detail::CompositeHash;



    RecordVal(RecordTypePtr t, std::vector<std::optional<ZVal>> init_vals);

    RecordValPtr DoCoerceTo(RecordTypePtr other, bool allow_orphaning) const;










    void AppendField(ValPtr v, const TypePtr& t) {
        assert(num_fields < static_cast<size_t>(GetRecordType()->NumFields()));
        if ( v )
            record_val[num_fields++] = ZValElement(v, t);
        else
            record_val[num_fields++] = ZValElement(t);
    }





    ZValElement& RawOptField(int field) {
        auto& f = record_val[field];
        if ( ! f ) {
            const auto& fi = GetRecordType()->DeferredInits()[field];
            if ( fi )
                f = fi->Generate();
        }

        return f;
    }

    ZVal& RawField(int field) {
        auto& f = RawOptField(field);
        if ( ! f )
            f = ZVal();

        assert(f.IsSet());
        return *f;
    }

    ValPtr DoClone(CloneState* state) override;

    void AddedField(int field) { Modified(); }

    Obj* origin = nullptr;

    using RecordTypeValMap = std::unordered_map<const RecordType*, std::vector<RecordValPtr>>;
    static RecordTypeValMap parse_time_records;

private:

    RecordVal* Get() { return this; }

    const RecordType* GetRecordType() const noexcept {
        assert(type->Tag() == TYPE_RECORD);
        return static_cast<RecordType*>(type.get());
    }







    void Init(ZValElement* elements) {
        const auto* rt = GetRecordType();
        size_t n = NumFields();
        assert(n == rt->Types()->size());
        for ( size_t i = 0; i < n; i++ )
            elements[i] = *rt->FieldDecl(i);
    }

    unsigned int ComputeFootprint(std::unordered_set<const Val*>* analyzed_vals) const override;


    size_t num_fields = 0;

    std::unique_ptr<ZValElement[]> record_val;
};

class EnumVal final : public detail::IntValImplementation {
public:
    ValPtr SizeVal() const override;

protected:
    friend class Val;
    friend class EnumType;

    friend EnumValPtr make_enum__CPP(TypePtr t, zeek_int_t i);

    template<class T, class... Ts>
    friend IntrusivePtr<T> make_intrusive(Ts&&... args);

    EnumVal(EnumTypePtr t, zeek_int_t i) : detail::IntValImplementation(std::move(t), i) {}

    void ValDescribe(ODesc* d) const override;
    ValPtr DoClone(CloneState* state) override;
};

class TypeVal final : public Val {
public:
    TypeVal(TypePtr t) : Val(std::move(t)) {}


    TypeVal(TypePtr t, bool type_type) : Val(make_intrusive<TypeType>(std::move(t))) {}

    zeek::Type* Get() const { return type.get(); }

protected:
    void ValDescribe(ODesc* d) const override;
    ValPtr DoClone(CloneState* state) override;
};

class VectorVal final : public Val, public notifier::detail::Modifiable {
public:
    explicit VectorVal(VectorTypePtr t);
    VectorVal(VectorTypePtr t, std::vector<std::optional<ZVal>>* vals);

    ~VectorVal() override;

    ValPtr SizeVal() const override;








    bool Assign(unsigned int index, ValPtr element);








    bool AssignRepeat(unsigned int index, unsigned int how_many, ValPtr element);



    bool AddTo(Val* v, bool is_first_init) const override;

    unsigned int Size() const { return vector_val.size(); }



    unsigned int Resize(unsigned int new_num_elements);


    unsigned int ResizeAtLeast(unsigned int new_num_elements);


    void Reserve(unsigned int num_elements);

    notifier::detail::Modifiable* Modifiable() override { return this; }









    bool Insert(unsigned int index, ValPtr element);







    bool Append(ValPtr element) { return Insert(Size(), std::move(element)); }


    bool Remove(unsigned int index);






    void Sort(Func* cmp_func = nullptr);









    VectorValPtr Order(Func* cmp_func = nullptr);















    bool Concretize(const TypePtr& t);

    ValPtr ValAt(unsigned int index) const { return At(index); }

    bool Has(unsigned int index) const { return index < vector_val.size() && vector_val[index]; }









    zeek_int_t IntAt(unsigned int index) const { return vector_val[index]->int_val; }
    zeek_uint_t CountAt(unsigned int index) const { return vector_val[index]->uint_val; }
    double DoubleAt(unsigned int index) const { return vector_val[index]->double_val; }
    const RecordVal* RecordValAt(unsigned int index) const { return vector_val[index]->record_val; }
    bool BoolAt(unsigned int index) const { return static_cast<bool>(vector_val[index]->uint_val); }
    const StringVal* StringValAt(unsigned int index) const { return vector_val[index]->string_val; }
    const String* StringAt(unsigned int index) const { return StringValAt(index)->AsString(); }


    const std::vector<std::optional<ZVal>>& RawVec() const { return vector_val; }
    std::vector<std::optional<ZVal>>& RawVec() { return vector_val; }

    const auto& RawYieldType() const { return yield_type; }
    const auto& RawYieldTypes() const { return yield_types; }

protected:









    ValPtr At(unsigned int index) const;

    void ValDescribe(ODesc* d) const override;

    unsigned int ComputeFootprint(std::unordered_set<const Val*>* analyzed_vals) const override;

    ValPtr DoClone(CloneState* state) override;

private:

    friend class RecordVal;
    VectorVal* Get() { return this; }




    bool CheckElementType(const ValPtr& element);


    void AddHoles(int nholes);

    std::vector<std::optional<ZVal>> vector_val;




    TypePtr yield_type;



    bool any_yield;



    bool managed_yield;







    std::vector<TypePtr>* yield_types = nullptr;
};


#define UNDERLYING_ACCESSOR_DEF(ztype, ctype, name)                                                                    \
    inline ctype Val::name() const { return static_cast<const ztype*>(this)->Get(); }

UNDERLYING_ACCESSOR_DEF(detail::IntValImplementation, zeek_int_t, AsInt)
UNDERLYING_ACCESSOR_DEF(BoolVal, bool, AsBool)
UNDERLYING_ACCESSOR_DEF(EnumVal, zeek_int_t, AsEnum)
UNDERLYING_ACCESSOR_DEF(detail::UnsignedValImplementation, zeek_uint_t, AsCount)
UNDERLYING_ACCESSOR_DEF(detail::DoubleValImplementation, double, AsDouble)
UNDERLYING_ACCESSOR_DEF(TimeVal, double, AsTime)
UNDERLYING_ACCESSOR_DEF(IntervalVal, double, AsInterval)
UNDERLYING_ACCESSOR_DEF(SubNetVal, const IPPrefix&, AsSubNet)
UNDERLYING_ACCESSOR_DEF(AddrVal, const IPAddr&, AsAddr)
UNDERLYING_ACCESSOR_DEF(StringVal, const String*, AsString)
UNDERLYING_ACCESSOR_DEF(FuncVal, Func*, AsFunc)
UNDERLYING_ACCESSOR_DEF(FileVal, File*, AsFile)
UNDERLYING_ACCESSOR_DEF(PatternVal, const RE_Matcher*, AsPattern)
UNDERLYING_ACCESSOR_DEF(TableVal, const PDict<TableEntryVal>*, AsTable)
UNDERLYING_ACCESSOR_DEF(TypeVal, zeek::Type*, AsType)





extern ValPtr check_and_promote(ValPtr v, const TypePtr& new_type, bool is_init,
                                const detail::Location* expr_location = nullptr);

extern bool same_atomic_val(const Val* v1, const Val* v2);
extern bool is_atomic_val(const Val* v);
extern void describe_vals(const ValPList* vals, ODesc* d, int offset = 0);
extern void describe_vals(const std::vector<ValPtr>& vals, ODesc* d, size_t offset = 0);
extern void delete_vals(ValPList* vals);


inline bool is_vector(Val* v) { return v->GetType()->Tag() == TYPE_VECTOR; }
inline bool is_vector(const ValPtr& v) { return is_vector(v.get()); }





extern ValPtr cast_value_to_type(Val* v, Type* t);





extern ValPtr attempt_to_cast_value_to_type(Val* v, Type* t, std::string& err);


inline ValPtr attempt_to_cast_value_to_type(Val* v, Type* t) {
    std::string err;
    return attempt_to_cast_value_to_type(v, t, err);
}







extern bool can_cast_any_to_type(const Val* v, Type* t);





extern bool can_cast_type_to_type(const Type* s, Type* t);

namespace detail {






extern zeek::expected<ValPtr, std::string> ValFromJSON(std::string_view json_str, const TypePtr& t,
                                                       const FuncPtr& key_func);





extern void concretize_if_unspecified(VectorValPtr v, TypePtr t);

}

}
