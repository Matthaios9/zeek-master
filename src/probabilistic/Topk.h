

#pragma once

#include <list>

#include "zeek/OpaqueVal.h"
#include "zeek/Val.h"







namespace zeek::detail {
class CompositeHash;
}

namespace zeek::probabilistic::detail {

struct Element;

struct Bucket {
    uint64_t count;
    std::list<Element*> elements;




    std::list<Bucket*>::iterator bucketPos;
};

struct Element {
    uint64_t epsilon;
    ValPtr value;
    Bucket* parent;
};

class TopkVal : public OpaqueVal {
public:







    explicit TopkVal(uint64_t size);




    ~TopkVal() override;








    void Encountered(ValPtr value);










    VectorValPtr GetTopK(int k) const;










    uint64_t GetCount(Val* value) const;










    uint64_t GetEpsilon(Val* value) const;






    uint64_t GetSize() const { return size; }








    uint64_t GetSum() const;











    void Merge(const TopkVal* value, bool doPrune = false);








    ValPtr DoClone(CloneState* state) override;

    DECLARE_OPAQUE_VALUE_DATA(TopkVal)

protected:



    TopkVal();

private:







    void IncrementCounter(Element* e, unsigned int count = 1);








    zeek::detail::HashKey* GetHash(Val* v) const;
    zeek::detail::HashKey* GetHash(const ValPtr& v) const { return GetHash(v.get()); }






    void Typify(TypePtr t);

    TypePtr type;
    zeek::detail::CompositeHash* hash = nullptr;
    std::list<Bucket*> buckets;
    PDict<Element>* elementDict = nullptr;
    uint64_t size = 0;
    uint64_t numElements = 0;
    bool pruned = false;
};

}
