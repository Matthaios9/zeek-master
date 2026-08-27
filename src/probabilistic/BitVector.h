

#pragma once

#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <vector>

namespace zeek {

class BrokerData;
class BrokerDataView;

}

namespace zeek::probabilistic::detail {




class BitVector {
public:
    using block_type = uint64_t;
    using size_type = size_t;
    using const_reference = bool;

    static size_type npos;
    static block_type bits_per_block;




    class Reference {
    public:



        Reference& Flip();

        operator bool() const;
        bool operator~() const;
        Reference& operator=(bool x);
        Reference& operator=(const Reference& other);
        Reference& operator|=(bool x);
        Reference& operator&=(bool x);
        Reference& operator^=(bool x);
        Reference& operator-=(bool x);

    private:
        friend class BitVector;

        Reference(block_type& block, block_type i);
        void operator&();

        block_type& block;
        const block_type mask;
    };




    BitVector();






    explicit BitVector(size_type size, bool value = false);








    template<std::input_iterator InputIterator>
    BitVector(InputIterator first, InputIterator last) {
        bits.insert(bits.end(), first, last);
        num_bits = bits.size() * bits_per_block;
    }





    BitVector(const BitVector& other);





    BitVector& operator=(const BitVector& other);




    BitVector operator~() const;
    BitVector operator<<(size_type n) const;
    BitVector operator>>(size_type n) const;
    BitVector& operator<<=(size_type n);
    BitVector& operator>>=(size_type n);
    BitVector& operator&=(BitVector const& other);
    BitVector& operator|=(BitVector const& other);
    BitVector& operator^=(BitVector const& other);
    BitVector& operator-=(BitVector const& other);
    friend BitVector operator&(BitVector const& x, BitVector const& y);
    friend BitVector operator|(BitVector const& x, BitVector const& y);
    friend BitVector operator^(BitVector const& x, BitVector const& y);
    friend BitVector operator-(BitVector const& x, BitVector const& y);




    friend bool operator==(BitVector const& x, BitVector const& y);
    friend bool operator!=(BitVector const& x, BitVector const& y);
    friend bool operator<(BitVector const& x, BitVector const& y);











    template<std::forward_iterator ForwardIterator>
    void Append(ForwardIterator first, ForwardIterator last) {
        if ( first == last )
            return;

        block_type excess = extra_bits();
        auto delta = std::distance(first, last);

        bits.reserve(Blocks() + delta);

        if ( excess == 0 ) {
            bits.back() |= (*first << excess);

            do {
                block_type b = *first++ >> (bits_per_block - excess);
                bits.push_back(b | (first == last ? 0 : *first << excess));
            } while ( first != last );
        }

        else
            bits.insert(bits.end(), first, last);

        num_bits += bits_per_block * delta;
    }





    void Append(block_type block);




    void PushBack(bool bit);




    void Clear();






    void Resize(size_type n, bool value = false);







    BitVector& Set(size_type i, bool bit = true);





    BitVector& Set();






    BitVector& Reset(size_type i);





    BitVector& Reset();






    BitVector& Flip(size_type i);





    BitVector& Flip();





    Reference operator[](size_type i);






    const_reference operator[](size_type i) const;






    size_type Count() const;





    size_type Blocks() const;





    size_type Size() const;





    bool Empty() const;





    bool AllZero() const;






    size_type FindFirst() const;









    size_type FindNext(size_type i) const;






    uint64_t Hash() const;

    std::optional<BrokerData> Serialize() const;
    static std::unique_ptr<BitVector> Unserialize(BrokerDataView data);

private:



    block_type extra_bits() const;






    void zero_unused_bits();







    size_type find_from(size_type i) const;




    static size_type block_index(size_type i) { return i / bits_per_block; }




    static block_type bit_index(size_type i) { return i % bits_per_block; }




    static block_type bit_mask(size_type i) { return static_cast<block_type>(1) << bit_index(i); }







    static size_type bits_to_blocks(size_type bits) {
        return bits / bits_per_block + static_cast<size_type>(bits % bits_per_block != 0);
    }






    static size_type lowest_bit(block_type block);

    std::vector<block_type> bits;
    size_type num_bits;
};

}
