

#pragma once

#include <broker/expected.hh>
#include <memory>

#include "zeek/Hash.h"

namespace zeek {
class BrokerData;
class BrokerDataView;
}

namespace zeek::probabilistic::detail {


enum HasherType : uint8_t { Default, Double };





class Hasher {
public:
    using digest = zeek::detail::hash_t;
    using digest_vector = std::vector<digest>;
    struct seed_t {

        alignas(16) unsigned long long h[2];

        friend seed_t operator+(seed_t lhs, const uint64_t rhs) {
            lhs.h[0] += rhs;
            return lhs;
        }
    };













    static seed_t MakeSeed(const void* data, size_t size);




    virtual ~Hasher() = default;








    template<typename T>
    digest_vector operator()(const T& x) const {
        return Hash(&x, sizeof(T));
    }








    digest_vector Hash(const zeek::detail::HashKey* key) const;











    virtual digest_vector Hash(const void* x, size_t n) const = 0;




    virtual Hasher* Clone() const = 0;




    virtual bool Equals(const Hasher* other) const = 0;




    size_t K() const { return k; }




    seed_t Seed() const { return seed; }

    std::optional<BrokerData> Serialize() const;
    static std::unique_ptr<Hasher> Unserialize(BrokerDataView data);

protected:
    Hasher() = default;








    Hasher(size_t arg_k, seed_t arg_seed);

    virtual HasherType Type() const = 0;

private:
    size_t k = 0;
    seed_t seed = {0};
};





class UHF {
public:



    UHF();







    explicit UHF(Hasher::seed_t arg_seed);

    template<typename T>
    Hasher::digest operator()(const T& x) const {
        return hash(&x, sizeof(T));
    }








    Hasher::digest operator()(const void* x, size_t n) const { return hash(x, n); }











    Hasher::digest hash(const void* x, size_t n) const;

    friend bool operator==(const UHF& x, const UHF& y) {
        return (x.seed.h[0] == y.seed.h[0]) && (x.seed.h[1] == y.seed.h[1]);
    }

    friend bool operator!=(const UHF& x, const UHF& y) { return ! (x == y); }

    std::optional<BrokerData> Serialize() const;
    static UHF Unserialize(BrokerDataView data);

private:
    static size_t compute_seed(Hasher::seed_t seed);

    Hasher::seed_t seed;
};





class DefaultHasher : public Hasher {
public:







    DefaultHasher(size_t k, Hasher::seed_t seed);


    digest_vector Hash(const void* x, size_t n) const final;
    DefaultHasher* Clone() const final;
    bool Equals(const Hasher* other) const final;

private:
    DefaultHasher() = default;

    HasherType Type() const override { return HasherType::Default; }

    std::vector<UHF> hash_functions;
};





class DoubleHasher : public Hasher {
public:







    DoubleHasher(size_t k, Hasher::seed_t seed);


    digest_vector Hash(const void* x, size_t n) const final;
    DoubleHasher* Clone() const final;
    bool Equals(const Hasher* other) const final;

private:
    DoubleHasher() = default;

    HasherType Type() const override { return HasherType::Double; }

    UHF h1;
    UHF h2;
};

}
