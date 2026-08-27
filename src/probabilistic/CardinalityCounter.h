

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace zeek {
class BrokerData;
class BrokerDataView;
}

namespace zeek::probabilistic::detail {




class CardinalityCounter {
public:















    explicit CardinalityCounter(double error_margin, double confidence = 0.95);




    CardinalityCounter(CardinalityCounter& other);




    CardinalityCounter(CardinalityCounter&& o) noexcept;









    explicit CardinalityCounter(uint64_t size);




    ~CardinalityCounter() = default;









    void AddElement(uint64_t hash);








    double Size() const;










    bool Merge(CardinalityCounter* c);

    std::optional<BrokerData> Serialize() const;
    static std::unique_ptr<CardinalityCounter> Unserialize(BrokerDataView data);

protected:





    uint64_t GetM() const;









    const std::vector<uint8_t>& GetBuckets() const;

private:




    explicit CardinalityCounter(uint64_t size, uint64_t V, double alpha_m);






    void Init(uint64_t arg_size);


















    int OptimalB(double error, double confidence) const;











    uint8_t Rank(uint64_t hash_modified) const;




    static int flsll(uint64_t mask);






    uint64_t m = 0;







    std::vector<uint8_t> buckets;







    uint64_t V = 0;
    double alpha_m = 0.0;
    int p = 0;
};

}
