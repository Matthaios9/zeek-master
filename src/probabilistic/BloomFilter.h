

#pragma once

#include <memory>
#include <string>

#include "zeek/probabilistic/BitVector.h"
#include "zeek/probabilistic/Hasher.h"

namespace zeek {
class BrokerData;
class BrokerDataView;
}

namespace zeek::probabilistic {

namespace detail {
class CounterVector;
}


enum BloomFilterType : uint8_t { Basic, Counting };




class BloomFilter {
public:



    virtual ~BloomFilter();







    virtual void Add(const zeek::detail::HashKey* key) = 0;









    virtual bool Decrement(const zeek::detail::HashKey* key) = 0;








    virtual size_t Count(const zeek::detail::HashKey* key) const = 0;






    virtual bool Empty() const = 0;




    virtual void Clear() = 0;








    virtual bool Merge(const BloomFilter* other) = 0;








    virtual BloomFilter* Intersect(const BloomFilter* other) const = 0;






    virtual BloomFilter* Clone() const = 0;





    virtual std::string InternalState() const = 0;

    std::optional<BrokerData> SerializeData() const;
    static std::unique_ptr<BloomFilter> UnserializeData(BrokerDataView data);

protected:



    BloomFilter();






    explicit BloomFilter(const detail::Hasher* hasher);

    virtual broker::expected<broker::data> DoSerialize() const;
    virtual bool DoUnserialize(const broker::data& data);
    virtual std::optional<BrokerData> DoSerializeData() const;
    virtual bool DoUnserializeData(BrokerDataView data);
    virtual BloomFilterType Type() const = 0;

    const detail::Hasher* hasher;
};

class CountingBloomFilter;




class BasicBloomFilter : public BloomFilter {
    friend class CountingBloomFilter;

public:









    BasicBloomFilter(const detail::Hasher* hasher, size_t cells);




    ~BasicBloomFilter() override;














    static size_t M(double fp, size_t capacity);












    static size_t K(size_t cells, size_t capacity);


    bool Empty() const override;
    void Clear() override;
    bool Merge(const BloomFilter* other) override;
    BasicBloomFilter* Clone() const override;
    BasicBloomFilter* Intersect(const BloomFilter* other) const override;
    std::string InternalState() const override;

protected:
    friend class BloomFilter;




    BasicBloomFilter();


    void Add(const zeek::detail::HashKey* key) override;
    bool Decrement(const zeek::detail::HashKey* key) override;
    size_t Count(const zeek::detail::HashKey* key) const override;
    std::optional<BrokerData> DoSerializeData() const override;
    bool DoUnserializeData(BrokerDataView data) override;
    BloomFilterType Type() const override { return BloomFilterType::Basic; }

private:
    detail::BitVector* bits;
};




class CountingBloomFilter : public BloomFilter {
public:










    CountingBloomFilter(const detail::Hasher* hasher, size_t cells, size_t width);




    ~CountingBloomFilter() override;


    bool Empty() const override;
    void Clear() override;
    bool Merge(const BloomFilter* other) override;
    CountingBloomFilter* Clone() const override;
    std::string InternalState() const override;













    BasicBloomFilter* Intersect(const BloomFilter* other) const override;

protected:
    friend class BloomFilter;




    CountingBloomFilter();


    void Add(const zeek::detail::HashKey* key) override;
    bool Decrement(const zeek::detail::HashKey* key) override;
    size_t Count(const zeek::detail::HashKey* key) const override;
    std::optional<BrokerData> DoSerializeData() const override;
    bool DoUnserializeData(BrokerDataView data) override;
    BloomFilterType Type() const override { return BloomFilterType::Counting; }

private:
    detail::CounterVector* cells;
};

}
