

#pragma once

#ifdef _MSC_VER
#include <unistd.h>
#endif

#include <broker/expected.hh>
#include <paraglob/paraglob.h>
#include <sys/types.h>
#include <optional>

#include "zeek/IntrusivePtr.h"
#include "zeek/RandTest.h"
#include "zeek/Val.h"
#include "zeek/digest.h"

namespace broker {
class data;
}

namespace zeek {

class BrokerData;
class BrokerDataView;
class BrokerListView;

namespace probabilistic {
class BloomFilter;
}
namespace probabilistic::detail {
class CardinalityCounter;
}

class OpaqueVal;
using OpaqueValPtr = IntrusivePtr<OpaqueVal>;

class BloomFilterVal;
using BloomFilterValPtr = IntrusivePtr<BloomFilterVal>;





class OpaqueMgr {
public:
    using Factory = OpaqueValPtr();










    const std::string& TypeID(const OpaqueVal* v) const;












    OpaqueValPtr Instantiate(const std::string& id) const;


    static OpaqueMgr* mgr();





    template<class T>
    class Register {
    public:
        Register(const char* id) { OpaqueMgr::mgr()->_types.emplace(id, &T::OpaqueInstantiate); }
    };

private:
    std::unordered_map<std::string, Factory*> _types;
};







#define DECLARE_OPAQUE_VALUE_DATA(T)                                                                                   \
    friend class zeek::OpaqueMgr::Register<T>;                                                                         \
    friend zeek::IntrusivePtr<T> zeek::make_intrusive<T>();                                                            \
    std::optional<zeek::BrokerData> DoSerializeData() const override;                                                  \
    bool DoUnserializeData(zeek::BrokerDataView data) override;                                                        \
    const char* OpaqueName() const override { return #T; }                                                             \
    static zeek::OpaqueValPtr OpaqueInstantiate() { return zeek::make_intrusive<T>(); }


#define __OPAQUE_MERGE(a, b) a##b
#define __OPAQUE_ID(x) __OPAQUE_MERGE(_opaque, x)


#define IMPLEMENT_OPAQUE_VALUE(T) static zeek::OpaqueMgr::Register<T> __OPAQUE_ID(__LINE__)(#T);








class OpaqueVal : public Val {
public:
    explicit OpaqueVal(OpaqueTypePtr t);




    std::optional<BrokerData> SerializeData() const;




    static OpaqueValPtr UnserializeData(BrokerDataView data);




    static OpaqueValPtr UnserializeData(BrokerListView data);

protected:
    friend class Val;
    friend class OpaqueMgr;








    virtual std::optional<BrokerData> DoSerializeData() const;







    virtual bool DoUnserializeData(BrokerDataView data);





    virtual const char* OpaqueName() const = 0;







    ValPtr DoClone(CloneState* state) override;





    static std::optional<BrokerData> SerializeType(const TypePtr& t);





    static TypePtr UnserializeType(BrokerDataView data);

    void ValDescribe(ODesc* d) const override;
    void ValDescribeReST(ODesc* d) const override;
};

class HashVal : public OpaqueVal {
public:
    template<class T>
    static void digest_all(detail::HashAlgorithm alg, const T& vlist, u_char* result) {
        auto h = detail::hash_init(alg);

        for ( const auto& v : vlist )
            digest_one(h, v);

        detail::hash_final(h, result);
    }

    bool IsValid() const;
    bool Init();
    bool Feed(const void* data, size_t size);
    StringValPtr Get();

protected:
    static void digest_one(detail::HashDigestState* h, const Val* v);
    static void digest_one(detail::HashDigestState* h, const ValPtr& v);

    explicit HashVal(OpaqueTypePtr t);

    virtual bool DoInit();
    virtual bool DoFeed(const void* data, size_t size);
    virtual StringValPtr DoGet();

private:

    bool valid;
};

class MD5Val : public HashVal {
public:
    struct State;

    using StatePtr = State*;

    template<class T>
    static void digest(const T& vlist, u_char result[ZEEK_MD5_DIGEST_LENGTH]) {
        digest_all(detail::Hash_MD5, vlist, result);
    }

    template<class T>
    static void hmac(const T& vlist, u_char key[ZEEK_MD5_DIGEST_LENGTH], u_char result[ZEEK_MD5_DIGEST_LENGTH]) {
        digest(vlist, result);

        for ( size_t i = 0; i < ZEEK_MD5_DIGEST_LENGTH; ++i )
            result[i] ^= key[i];

        detail::calculate_digest(detail::Hash_MD5, result, ZEEK_MD5_DIGEST_LENGTH, result);
    }

    MD5Val();
    ~MD5Val() override;

    ValPtr DoClone(CloneState* state) override;

protected:
    friend class Val;

    bool DoInit() override;
    bool DoFeed(const void* data, size_t size) override;
    StringValPtr DoGet() override;

    DECLARE_OPAQUE_VALUE_DATA(MD5Val)
private:
    StatePtr ctx = nullptr;
};

class SHA1Val : public HashVal {
public:
    struct State;

    using StatePtr = State*;

    template<class T>
    static void digest(const T& vlist, u_char result[ZEEK_SHA_DIGEST_LENGTH]) {
        digest_all(detail::Hash_SHA1, vlist, result);
    }

    SHA1Val();
    ~SHA1Val() override;

    ValPtr DoClone(CloneState* state) override;

protected:
    friend class Val;

    bool DoInit() override;
    bool DoFeed(const void* data, size_t size) override;
    StringValPtr DoGet() override;

    DECLARE_OPAQUE_VALUE_DATA(SHA1Val)
private:
    StatePtr ctx = nullptr;
};

class SHA224Val : public HashVal {
public:
    struct State;

    using StatePtr = State*;

    template<class T>
    static void digest(const T& vlist, u_char result[ZEEK_SHA224_DIGEST_LENGTH]) {
        digest_all(detail::Hash_SHA224, vlist, result);
    }

    SHA224Val();
    ~SHA224Val() override;

    ValPtr DoClone(CloneState* state) override;

protected:
    friend class Val;

    bool DoInit() override;
    bool DoFeed(const void* data, size_t size) override;
    StringValPtr DoGet() override;

    DECLARE_OPAQUE_VALUE_DATA(SHA224Val)
private:
    StatePtr ctx = nullptr;
};

class SHA256Val : public HashVal {
public:
    struct State;

    using StatePtr = State*;

    template<class T>
    static void digest(const T& vlist, u_char result[ZEEK_SHA256_DIGEST_LENGTH]) {
        digest_all(detail::Hash_SHA256, vlist, result);
    }

    template<class T>
    static void hmac(const T& vlist, u_char key[ZEEK_SHA256_DIGEST_LENGTH], u_char result[ZEEK_SHA256_DIGEST_LENGTH]) {
        digest(vlist, result);

        for ( size_t i = 0; i < ZEEK_SHA256_DIGEST_LENGTH; ++i )
            result[i] ^= key[i];

        detail::calculate_digest(detail::Hash_SHA256, result, ZEEK_SHA256_DIGEST_LENGTH, result);
    }

    SHA256Val();
    ~SHA256Val() override;

    ValPtr DoClone(CloneState* state) override;

protected:
    friend class Val;

    bool DoInit() override;
    bool DoFeed(const void* data, size_t size) override;
    StringValPtr DoGet() override;

    DECLARE_OPAQUE_VALUE_DATA(SHA256Val)
private:
    StatePtr ctx = nullptr;
};

class SHA384Val : public HashVal {
public:
    struct State;

    using StatePtr = State*;

    template<class T>
    static void digest(const T& vlist, u_char result[ZEEK_SHA384_DIGEST_LENGTH]) {
        digest_all(detail::Hash_SHA384, vlist, result);
    }

    SHA384Val();
    ~SHA384Val() override;

    ValPtr DoClone(CloneState* state) override;

protected:
    friend class Val;

    bool DoInit() override;
    bool DoFeed(const void* data, size_t size) override;
    StringValPtr DoGet() override;

    DECLARE_OPAQUE_VALUE_DATA(SHA384Val)
private:
    StatePtr ctx = nullptr;
};

class SHA512Val : public HashVal {
public:
    struct State;

    using StatePtr = State*;

    template<class T>
    static void digest(const T& vlist, u_char result[ZEEK_SHA512_DIGEST_LENGTH]) {
        digest_all(detail::Hash_SHA512, vlist, result);
    }

    SHA512Val();
    ~SHA512Val() override;

    ValPtr DoClone(CloneState* state) override;

protected:
    friend class Val;

    bool DoInit() override;
    bool DoFeed(const void* data, size_t size) override;
    StringValPtr DoGet() override;

    DECLARE_OPAQUE_VALUE_DATA(SHA512Val)
private:
    StatePtr ctx = nullptr;
};

class EntropyVal : public OpaqueVal {
public:
    EntropyVal();

    bool Feed(const void* data, size_t size);
    bool Get(double* r_ent, double* r_chisq, double* r_mean, double* r_montepicalc, double* r_scc);

protected:
    friend class Val;

    DECLARE_OPAQUE_VALUE_DATA(EntropyVal)
private:
    detail::RandTest state;
};

class BloomFilterVal : public OpaqueVal {
public:
    explicit BloomFilterVal(probabilistic::BloomFilter* bf);
    ~BloomFilterVal() override;


    BloomFilterVal(const BloomFilterVal&) = delete;
    BloomFilterVal& operator=(const BloomFilterVal&) = delete;

    ValPtr DoClone(CloneState* state) override;

    const TypePtr& Type() const { return type; }

    bool Typify(TypePtr type);

    void Add(const Val* val);
    bool Decrement(const Val* val);
    size_t Count(const Val* val) const;
    void Clear();
    bool Empty() const;
    std::string InternalState() const;

    static BloomFilterValPtr Merge(const BloomFilterVal* x, const BloomFilterVal* y);
    static BloomFilterValPtr Intersect(const BloomFilterVal* x, const BloomFilterVal* y);

protected:
    friend class Val;
    BloomFilterVal();

    DECLARE_OPAQUE_VALUE_DATA(BloomFilterVal)
private:
    TypePtr type;
    detail::CompositeHash* hash;
    probabilistic::BloomFilter* bloom_filter;
};

class CardinalityVal : public OpaqueVal {
public:
    explicit CardinalityVal(probabilistic::detail::CardinalityCounter*);
    ~CardinalityVal() override;

    ValPtr DoClone(CloneState* state) override;

    void Add(const Val* val);

    const TypePtr& Type() const { return type; }

    bool Typify(TypePtr type);

    probabilistic::detail::CardinalityCounter* Get() { return c; };

protected:
    CardinalityVal();

    DECLARE_OPAQUE_VALUE_DATA(CardinalityVal)
private:
    TypePtr type;
    detail::CompositeHash* hash;
    probabilistic::detail::CardinalityCounter* c;
};

class ParaglobVal : public OpaqueVal {
public:
    explicit ParaglobVal(std::unique_ptr<paraglob::Paraglob> p);
    VectorValPtr Get(StringVal*& pattern);
    ValPtr DoClone(CloneState* state) override;
    bool operator==(const ParaglobVal& other) const;

protected:
    ParaglobVal() : OpaqueVal(paraglob_type) {}

    DECLARE_OPAQUE_VALUE_DATA(ParaglobVal)

private:
    std::unique_ptr<paraglob::Paraglob> internal_paraglob;
};

}
