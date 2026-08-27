

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace zeek {
class BrokerData;
class BrokerDataView;
}

namespace zeek::probabilistic::detail {

class BitVector;




class CounterVector {
public:
    using size_type = size_t;
    using count_type = uint64_t;










    explicit CounterVector(size_t width, size_t cells = 1024);






    CounterVector(const CounterVector& other);




    virtual ~CounterVector();

    CounterVector& operator=(const CounterVector&) = delete;












    bool Increment(size_type cell, count_type value = 1);












    bool Decrement(size_type cell, count_type value = 1);










    count_type Count(size_type cell) const;





    bool AllZero() const;




    void Reset();






    size_type Size() const;






    size_t Width() const;






    size_t Max() const;











    CounterVector& Merge(const CounterVector& other);







    BitVector ToBitVector() const;




    CounterVector& operator|=(const CounterVector& other);






    uint64_t Hash() const;

    std::optional<BrokerData> Serialize() const;
    static std::unique_ptr<CounterVector> Unserialize(BrokerDataView data);

protected:
    friend CounterVector operator|(const CounterVector& x, const CounterVector& y);

    CounterVector() = default;

private:
    BitVector* bits = nullptr;
    size_t width = 0;
};

}
