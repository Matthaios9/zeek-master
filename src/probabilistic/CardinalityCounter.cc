

#include "zeek/probabilistic/CardinalityCounter.h"

#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <numbers>
#include <utility>

#include "zeek/Reporter.h"
#include "zeek/broker/Data.h"

namespace zeek::probabilistic::detail {

int CardinalityCounter::OptimalB(double error, double confidence) const {
    double initial_estimate = 2 * (log(1.04) - log(error)) / std::numbers::ln2;
    int answer = static_cast<int>(floor(initial_estimate));




    double k = 0;

    do {
        answer++;
        k = pow(2, (answer - initial_estimate) / 2);
    } while ( erf(k / std::numbers::sqrt2) < confidence );

    return answer;
}

void CardinalityCounter::Init(uint64_t size) {
    m = size;




    if ( m == 16 )
        alpha_m = 0.673;

    else if ( m == 32 )
        alpha_m = 0.697;

    else if ( m == 64 )
        alpha_m = 0.709;

    else if ( m >= 128 )
        alpha_m = 0.7213 / (1 + 1.079 / m);

    else
        reporter->InternalError("Invalid size %" PRIu64 ". Size either has to be 16, 32, 64 or bigger than 128", size);

    double calc_p = log2(m);
    if ( trunc(calc_p) != calc_p )
        reporter->InternalError("Invalid size %" PRIu64 ". Size either has to be a power of 2", size);

    p = calc_p;

    buckets.reserve(m);
    for ( uint64_t i = 0; i < m; i++ )
        buckets.push_back(0);

    assert(buckets.size() == m);

    V = m;
}

CardinalityCounter::CardinalityCounter(CardinalityCounter& other) : buckets(other.buckets) {
    V = other.V;
    alpha_m = other.alpha_m;
    m = other.m;
    p = other.p;
}

CardinalityCounter::CardinalityCounter(CardinalityCounter&& o) noexcept {
    V = o.V;
    alpha_m = o.alpha_m;
    m = o.m;
    p = o.p;

    o.m = 0;
    buckets = std::move(o.buckets);
}

CardinalityCounter::CardinalityCounter(double error_margin, double confidence) {
    int b = OptimalB(error_margin, confidence);
    Init(static_cast<uint64_t>(pow(2, b)));

    assert(b == p);
}

CardinalityCounter::CardinalityCounter(uint64_t size) { Init(size); }

CardinalityCounter::CardinalityCounter(uint64_t arg_size, uint64_t arg_V, double arg_alpha_m) {
    m = arg_size;

    buckets.reserve(m);
    for ( uint64_t i = 0; i < m; i++ )
        buckets.push_back(0);

    alpha_m = arg_alpha_m;
    V = arg_V;
    p = log2(m);
}

uint8_t CardinalityCounter::Rank(uint64_t hash_modified) const {
    hash_modified = hash_modified >> p;
    int answer = 64 - p - CardinalityCounter::flsll(hash_modified) + 1;
    assert(answer > 0 && answer < 64);

    return answer;
}

void CardinalityCounter::AddElement(uint64_t hash) {
    uint64_t index = hash % m;
    hash = hash - index;

    if ( buckets[index] == 0 )
        V--;

    uint8_t temp = Rank(hash);

    if ( temp > buckets[index] )
        buckets[index] = temp;
}










double CardinalityCounter::Size() const {
    double answer = 0;

    if ( m == 0 )
        return -1.0;

    for ( unsigned int i = 0; i < m; i++ )
        answer += pow(2, -(static_cast<int>(buckets[i])));

    answer = 1 / answer;
    answer = (alpha_m * m * m * answer);

    if ( answer <= 5.0 * ((static_cast<double>(m) / 2.0)) )
        return m * log(static_cast<double>(m) / V);

    else if ( answer <= (pow(2, 64) / 30) )
        return answer;

    else
        return -pow(2, 64) * log(1 - (answer / pow(2, 64)));
}

bool CardinalityCounter::Merge(CardinalityCounter* c) {
    if ( m != c->GetM() )
        return false;

    const std::vector<uint8_t>& temp = c->GetBuckets();

    V = 0;

    for ( size_t i = 0; i < m; i++ ) {
        if ( temp[i] > buckets[i] )
            buckets[i] = temp[i];

        if ( buckets[i] == 0 )
            ++V;
    }

    return true;
}

const std::vector<uint8_t>& CardinalityCounter::GetBuckets() const { return buckets; }

uint64_t CardinalityCounter::GetM() const { return m; }

std::optional<BrokerData> CardinalityCounter::Serialize() const {
    BrokerListBuilder builder;
    builder.Reserve(3 + m);
    builder.Add(m);
    builder.Add(V);
    builder.Add(alpha_m);

    for ( size_t i = 0; i < m; ++i )
        builder.AddCount(buckets[i]);

    return std::move(builder).Build();
}

std::unique_ptr<CardinalityCounter> CardinalityCounter::Unserialize(BrokerDataView data) {
    if ( ! data.IsList() )
        return nullptr;

    auto v = data.ToList();
    if ( v.Size() < 3 || ! are_all_counts(v[0], v[1]) || ! v[2].IsReal() )
        return nullptr;

    auto [m, V] = to_count(v[0], v[1]);
    auto alpha_m = v[2].ToReal();

    if ( v.Size() != 3 + m )
        return nullptr;

    auto cc = std::unique_ptr<CardinalityCounter>(new CardinalityCounter(m, V, alpha_m));
    if ( m != cc->m )
        return nullptr;
    if ( cc->buckets.size() != m )
        return nullptr;

    for ( size_t i = 0; i < m; ++i ) {
        auto x = v[3 + i];
        if ( ! x.IsCount() )
            return nullptr;

        cc->buckets[i] = x.ToCount();
    }

    return cc;
}





































int CardinalityCounter::flsll(uint64_t mask) {
    int bit;

    if ( mask == 0 )
        return (0);
    for ( bit = 1; mask != 1; bit++ )
        mask = static_cast<uint64_t>(mask) >> 1;
    return (bit);
}

}
