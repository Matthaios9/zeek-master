

#pragma once

#include <algorithm>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <memory>
#include <vector>

#include "zeek/Hash.h"
#include "zeek/Obj.h"
#include "zeek/Reporter.h"
#include "zeek/util.h"


using dict_delete_func = void (*)(void*);

#if defined(ZEEK_DICT_DEBUG)
#define ASSERT_VALID(o) o->AssertValid()
#define ASSERT_EQUAL(a, b) ASSERT(a == b)
#else
#define ASSERT_VALID(o)
#define ASSERT_EQUAL(a, b)
#endif

namespace zeek {

template<typename T>
class Dictionary;

enum DictOrder : uint8_t { ORDERED, UNORDERED };


extern void generic_delete_func(void*);

namespace detail {



constexpr uint32_t HASH_MASK = 0xFFFFFFFF;






constexpr uint8_t DICT_REMAP_ENTRIES = 16;




constexpr int MIN_DICT_LOAD_FACTOR_100 = 25;
constexpr int DICT_LOAD_FACTOR_100 = 75;



constexpr int SPACE_DISTANCE_THRESHOLD = 32;



constexpr int MIN_SPACE_DISTANCE_SAMPLES = 128;



constexpr uint8_t DEFAULT_DICT_SIZE = 0;




constexpr uint8_t DICT_THRESHOLD_BITS = 3;



constexpr uint16_t TOO_FAR_TO_REACH = 0xFFFF;




template<typename T>
class DictEntry {
public:
#ifdef ZEEK_DICT_DEBUG
    int bucket = 0;
#endif


    uint16_t distance = TOO_FAR_TO_REACH;



    uint32_t key_size = 0;



    static constexpr uint32_t MAX_KEY_SIZE = UINT32_MAX;


    uint32_t hash = 0;

    T* value = nullptr;
    union {
        char key_here[8];
        char* key;
    };

    DictEntry(void* arg_key, uint32_t key_size = 0, hash_t hash = 0, T* value = nullptr, int16_t d = TOO_FAR_TO_REACH,
              bool copy_key = false)
        : distance(d), key_size(key_size), hash(static_cast<uint32_t>(hash)), value(value) {
        if ( ! arg_key )
            return;

        if ( key_size <= 8 ) {
            memcpy(key_here, arg_key, key_size);
            if ( ! copy_key )
                delete[] reinterpret_cast<char*>(arg_key);
        }
        else {
            if ( copy_key ) {
                key = new char[key_size];
                memcpy(key, arg_key, key_size);
            }
            else {
                key = reinterpret_cast<char*>(arg_key);
            }
        }
    }

    bool Empty() const { return distance == TOO_FAR_TO_REACH; }
    void SetEmpty() {
        distance = TOO_FAR_TO_REACH;
#ifdef ZEEK_DICT_DEBUG

        hash = 0;
        key = nullptr;
        value = nullptr;
        key_size = 0;
        bucket = 0;
#endif
    }

    void Clear() {
        if ( key_size > 8 )
            delete[] key;
        SetEmpty();
    }

    const char* GetKey() const { return key_size <= 8 ? key_here : key; }
    std::unique_ptr<detail::HashKey> GetHashKey() const {
        return std::make_unique<detail::HashKey>(GetKey(), key_size, hash);
    }

    bool Equal(const char* arg_key, uint32_t arg_key_size, hash_t arg_hash) const {
        return (0 == ((hash ^ arg_hash) & HASH_MASK)) && key_size == arg_key_size &&
               0 == memcmp(GetKey(), arg_key, key_size);
    }

    bool operator==(const DictEntry& r) const { return Equal(r.GetKey(), r.key_size, r.hash); }
    bool operator!=(const DictEntry& r) const { return ! Equal(r.GetKey(), r.key_size, r.hash); }
};

using DictEntryVec = std::vector<detail::HashKey>;

}

template<typename T>
class DictIterator {
public:
    using value_type = detail::DictEntry<T>;
    using reference = detail::DictEntry<T>&;
    using pointer = detail::DictEntry<T>*;
    using difference_type = std::ptrdiff_t;
    using iterator_category = std::forward_iterator_tag;

    DictIterator() = default;
    ~DictIterator() {
        if ( dict ) {
            assert(dict->num_iterators > 0);
            dict->DecrIters();
        }
    }

    DictIterator(const DictIterator& that) {
        if ( this == &that )
            return;

        if ( dict ) {
            assert(dict->num_iterators > 0);
            dict->DecrIters();
        }

        dict = that.dict;
        curr = that.curr;
        end = that.end;
        ordered_iter = that.ordered_iter;

        dict->IncrIters();
    }

    DictIterator& operator=(const DictIterator& that) {
        if ( this == &that )
            return *this;

        if ( dict ) {
            assert(dict->num_iterators > 0);
            dict->DecrIters();
        }

        dict = that.dict;
        curr = that.curr;
        end = that.end;
        ordered_iter = that.ordered_iter;

        dict->IncrIters();

        return *this;
    }

    DictIterator(DictIterator&& that) noexcept {
        if ( this == &that )
            return;

        if ( dict ) {
            assert(dict->num_iterators > 0);
            dict->DecrIters();
        }

        dict = that.dict;
        curr = that.curr;
        end = that.end;
        ordered_iter = that.ordered_iter;

        that.dict = nullptr;
    }

    DictIterator& operator=(DictIterator&& that) noexcept {
        if ( this == &that )
            return *this;

        if ( dict ) {
            assert(dict->num_iterators > 0);
            dict->DecrIters();
        }

        dict = that.dict;
        curr = that.curr;
        end = that.end;
        ordered_iter = that.ordered_iter;

        that.dict = nullptr;

        return *this;
    }

    reference operator*() {
        if ( dict->IsOrdered() ) {



            auto e = dict->LookupEntry(*ordered_iter);
            return *e;
        }

        return *curr;
    }
    reference operator*() const {
        if ( dict->IsOrdered() ) {
            auto e = dict->LookupEntry(*ordered_iter);
            return *e;
        }

        return *curr;
    }
    pointer operator->() {
        if ( dict->IsOrdered() )
            return dict->LookupEntry(*ordered_iter);

        return curr;
    }
    pointer operator->() const {
        if ( dict->IsOrdered() )
            return dict->LookupEntry(*ordered_iter);

        return curr;
    }

    DictIterator& operator++() {
        if ( dict->IsOrdered() )
            ++ordered_iter;
        else {


            do {
                ++curr;
            } while ( curr != end && curr->Empty() );
        }

        return *this;
    }

    DictIterator operator++(int) {
        auto temp(*this);
        ++*this;
        return temp;
    }

    bool operator==(const DictIterator& that) const {
        if ( dict != that.dict )
            return false;

        if ( dict->IsOrdered() )
            return ordered_iter == that.ordered_iter;

        return curr == that.curr;
    }

    bool operator!=(const DictIterator& that) const { return ! (*this == that); }

private:
    friend class Dictionary<T>;

    DictIterator(const Dictionary<T>* d, detail::DictEntry<T>* begin, detail::DictEntry<T>* end)
        : curr(begin), end(end) {




        dict = const_cast<Dictionary<T>*>(d);


        while ( curr != end && curr->Empty() )
            ++curr;

        dict->IncrIters();
    }

    DictIterator(const Dictionary<T>* d, detail::DictEntryVec::iterator iter) : ordered_iter(iter) {




        dict = const_cast<Dictionary<T>*>(d);
        dict->IncrIters();
    }

    Dictionary<T>* dict = nullptr;
    detail::DictEntry<T>* curr = nullptr;
    detail::DictEntry<T>* end = nullptr;
    detail::DictEntryVec::iterator ordered_iter;
};

template<typename T>
class RobustDictIterator {
public:
    using value_type = detail::DictEntry<T>;
    using reference = detail::DictEntry<T>&;
    using pointer = detail::DictEntry<T>*;
    using difference_type = std::ptrdiff_t;
    using iterator_category = std::forward_iterator_tag;

    RobustDictIterator() : curr(nullptr) {}

    RobustDictIterator(Dictionary<T>* d) : curr(nullptr), dict(d) {
        next = -1;
        inserted = new std::vector<detail::DictEntry<T>>();
        visited = new std::vector<detail::DictEntry<T>>();

        dict->IncrIters();
        dict->iterators->push_back(this);


        curr = dict->GetNextRobustIteration(this);
    }

    RobustDictIterator(const RobustDictIterator& other) : curr(nullptr), dict(nullptr) { *this = other; }

    RobustDictIterator(RobustDictIterator&& other) noexcept : curr(nullptr), dict(nullptr) { *this = std::move(other); }

    ~RobustDictIterator() { Complete(); }

    reference operator*() { return curr; }
    pointer operator->() { return &curr; }

    RobustDictIterator& operator++() {
        if ( dict )
            curr = dict->GetNextRobustIteration(this);

        return *this;
    }

    RobustDictIterator operator++(int) {
        auto temp(*this);
        ++*this;
        return temp;
    }

    RobustDictIterator& operator=(const RobustDictIterator& other) {
        if ( this == &other )
            return *this;

        delete inserted;
        inserted = nullptr;

        delete visited;
        visited = nullptr;

        dict = nullptr;
        curr.Clear();
        next = -1;

        if ( other.dict ) {
            next = other.next;
            inserted = new std::vector<detail::DictEntry<T>>();
            visited = new std::vector<detail::DictEntry<T>>();

            if ( other.inserted )
                std::ranges::copy(*other.inserted, std::back_inserter(*inserted));

            if ( other.visited )
                std::ranges::copy(*other.visited, std::back_inserter(*visited));

            dict = other.dict;
            dict->IncrIters();
            dict->iterators->push_back(this);

            curr = other.curr;
        }

        return *this;
    }

    RobustDictIterator& operator=(RobustDictIterator&& other) noexcept {
        delete inserted;
        inserted = nullptr;

        delete visited;
        visited = nullptr;

        dict = nullptr;
        curr.Clear();
        next = -1;

        if ( other.dict ) {
            next = other.next;
            inserted = other.inserted;
            visited = other.visited;

            dict = other.dict;
            dict->iterators->push_back(this);
            dict->iterators->erase(std::remove(dict->iterators->begin(), dict->iterators->end(), &other),
                                   dict->iterators->end());
            other.dict = nullptr;

            curr = std::move(other.curr);
        }

        return *this;
    }

    bool operator==(const RobustDictIterator& that) const { return curr == that.curr; }
    bool operator!=(const RobustDictIterator& that) const { return ! (*this == that); }

private:
    friend class Dictionary<T>;

    void Complete() {
        if ( dict ) {
            assert(dict->num_iterators > 0);
            dict->DecrIters();

            dict->iterators->erase(std::remove(dict->iterators->begin(), dict->iterators->end(), this),
                                   dict->iterators->end());

            delete inserted;
            delete visited;

            inserted = nullptr;
            visited = nullptr;
            dict = nullptr;
            curr = nullptr;
        }
    }


    std::vector<detail::DictEntry<T>>* inserted = nullptr;



    std::vector<detail::DictEntry<T>>* visited = nullptr;

    detail::DictEntry<T> curr;
    Dictionary<T>* dict = nullptr;
    int next = -1;
};













template<typename T>
class Dictionary {
public:
    explicit Dictionary(DictOrder ordering = UNORDERED, int initial_size = detail::DEFAULT_DICT_SIZE) {
        if ( initial_size > 0 ) {


            SetLog2Buckets(static_cast<uint16_t>(std::log2(initial_size)));
            Init();
        }

        if ( ordering == ORDERED )
            order = std::make_unique<std::vector<detail::HashKey>>();
    }

    ~Dictionary() { Clear(); }






    T* Lookup(const detail::HashKey* key) const { return Lookup(key->Key(), key->Size(), key->Hash()); }

    T* Lookup(const void* key, int key_size, detail::hash_t h) const {
        if ( auto e = LookupEntry(key, key_size, h) )
            return e->value;

        return nullptr;
    }

    T* Lookup(const char* key) const {
        detail::HashKey h(key);
        return Dictionary<T>::Lookup(&h);
    }




    T* Insert(detail::HashKey* key, T* val, bool* iterators_invalidated = nullptr) {
        return Insert(key->TakeKey(), key->Size(), key->Hash(), val, false, iterators_invalidated);
    }






    T* Insert(void* key, uint64_t key_size, detail::hash_t hash, T* val, bool copy_key,
              bool* iterators_invalidated = nullptr) {
        ASSERT_VALID(this);



        if ( ! table )
            Init();

        T* v = nullptr;

        if ( key_size > detail::DictEntry<T>::MAX_KEY_SIZE ) {






            auto loc = detail::GetCurrentLocation();
            reporter->RuntimeError(&loc,
                                   "Attempted to create DictEntry with excessively large key, "
                                   "truncating key (%" PRIu64 " > %u)",
                                   key_size, detail::DictEntry<T>::MAX_KEY_SIZE);
        }




        int insert_position = -1;
        int insert_distance = -1;
        int position = LookupIndex(key, key_size, hash, &insert_position, &insert_distance);
        if ( position >= 0 ) {
            v = table[position].value;
            table[position].value = val;
            if ( ! copy_key )
                delete[] reinterpret_cast<char*>(key);

            if ( iterators && ! iterators->empty() )

                for ( auto c : *iterators ) {


                    if ( **c == table[position] )
                        (*c)->value = val;



                    auto it = std::ranges::find(*c->inserted, table[position]);
                    if ( it != c->inserted->end() )
                        it->value = val;
                }
        }
        else {
            if ( ! HaveOnlyRobustIterators() ) {
                if ( iterators_invalidated )
                    *iterators_invalidated = true;
                else
                    reporter->InternalWarning("Dictionary::Insert() possibly caused iterator invalidation");
            }



            if ( order )
                order->emplace_back(detail::HashKey{key, static_cast<size_t>(key_size), hash & detail::HASH_MASK});



            detail::DictEntry<T> entry(key, key_size, hash, val, insert_distance, copy_key);
            InsertRelocateAndAdjust(entry, insert_position);

            num_entries++;
            cum_entries++;
            if ( max_entries < num_entries )
                max_entries = num_entries;
            if ( num_entries > ThresholdEntries() )
                SizeUp();



            else if ( space_distance_samples > detail::MIN_SPACE_DISTANCE_SAMPLES &&
                      static_cast<uint64_t>(space_distance_sum) >
                          static_cast<uint64_t>(space_distance_samples) * detail::SPACE_DISTANCE_THRESHOLD &&
                      static_cast<int>(num_entries) > detail::MIN_DICT_LOAD_FACTOR_100 * Capacity() / 100 )
                SizeUp();
        }




        if ( Remapping() )
            Remap();
        ASSERT_VALID(this);
        return v;
    }

    T* Insert(const char* key, T* val, bool* iterators_invalidated = nullptr) {
        detail::HashKey h(key);
        return Insert(&h, val, iterators_invalidated);
    }






    T* Remove(const detail::HashKey* key, bool* iterators_invalidated = nullptr) {
        return Remove(key->Key(), key->Size(), key->Hash(), false, iterators_invalidated);
    }
    T* Remove(const void* key, int key_size, detail::hash_t hash, bool dont_delete = false,
              bool* iterators_invalidated =
                  nullptr) {
        ASSERT_VALID(this);

        ASSERT(! dont_delete);


        int position = LookupIndex(key, key_size, hash);
        if ( position < 0 )
            return nullptr;

        if ( ! HaveOnlyRobustIterators() ) {
            if ( iterators_invalidated )
                *iterators_invalidated = true;
            else
                reporter->InternalWarning("Dictionary::Remove() possibly caused iterator invalidation");
        }

        detail::DictEntry<T> entry = RemoveRelocateAndAdjust(position);
        num_entries--;
        ASSERT(num_entries >= 0);

        if ( order ) {
            for ( auto it = order->begin(); it != order->end(); ++it ) {
                if ( it->Equal(key, key_size, hash & detail::HASH_MASK) ) {
                    it = order->erase(it);
                    break;
                }
            }

            ASSERT(num_entries == order->size());
        }

        T* v = entry.value;
        entry.Clear();
        ASSERT_VALID(this);
        return v;
    }



    T* RemoveEntry(const detail::HashKey* key, bool* iterators_invalidated = nullptr) {
        return Remove(key->Key(), key->Size(), key->Hash(), false, iterators_invalidated);
    }
    T* RemoveEntry(const detail::HashKey& key, bool* iterators_invalidated = nullptr) {
        return Remove(key.Key(), key.Size(), key.Hash(), false, iterators_invalidated);
    }


    int Length() const { return num_entries; }


    int MaxLength() const { return max_entries; }


    uint64_t NumCumulativeInserts() const { return cum_entries; }


    int IsOrdered() const { return order != nullptr; }







    T* NthEntry(int n) const {
        const void* key;
        int key_len;
        return NthEntry(n, key, key_len);
    }

    T* NthEntry(int n, const void*& key, int& key_size) const {
        if ( ! order || n < 0 || n >= Length() )
            return nullptr;

        auto& hk = order->at(n);
        auto entry = Lookup(&hk);

        key = hk.Key();
        key_size = hk.Size();
        return entry;
    }

    T* NthEntry(int n, const char*& key) const {
        int key_len;
        return NthEntry(n, key, key_len);
    }

    void SetDeleteFunc(dict_delete_func f) { delete_func = f; }


    void Clear() {
        if ( table ) {
            for ( int i = Capacity() - 1; i >= 0; i-- ) {
                if ( table[i].Empty() )
                    continue;
                if ( delete_func )
                    delete_func(table[i].value);
                table[i].Clear();
            }
            free(table);
            table = nullptr;
        }

        if ( order )
            order.reset();

        if ( iterators ) {

            auto copied_iterators = *iterators;
            for ( auto* i : copied_iterators )
                i->Complete();

            delete iterators;
            iterators = nullptr;
        }
        log2_buckets = 0;
        num_iterators = 0;
        remaps = 0;
        remap_end = -1;
        num_entries = 0;
        max_entries = 0;
    }


    int Capacity() const { return table ? bucket_capacity : 0; }
    int ExpectedCapacity() const { return bucket_capacity; }


#ifdef ZEEK_DICT_DEBUG
    void DumpIfInvalid(bool valid) const {
        if ( ! valid ) {
            Dump(1);
            abort();
        }
    }

    void AssertValid() const {
        bool valid = true;
        int n = num_entries;

        if ( table )
            for ( int i = Capacity() - 1; i >= 0; i-- )
                if ( ! table[i].Empty() )
                    n--;

        valid = (n == 0);
        DumpIfInvalid(valid);


        for ( int i = 1; i < Capacity(); i++ ) {
            if ( ! table || table[i].Empty() )
                continue;

            if ( table[i - 1].Empty() ) {
                valid = (table[i].distance == 0);
                DumpIfInvalid(valid);
            }
            else {
                valid = (table[i].bucket >= table[i - 1].bucket);
                DumpIfInvalid(valid);

                if ( table[i].bucket == table[i - 1].bucket ) {
                    valid = (table[i].distance == table[i - 1].distance + 1);
                    DumpIfInvalid(valid);
                }
                else {
                    valid = (table[i].distance <= table[i - 1].distance);
                    DumpIfInvalid(valid);
                }
            }
        }
    }

#endif

    static constexpr size_t DICT_NUM_DISTANCES = 5;

    void Dump(int level = 0) const {
        int key_size = 0;
        for ( int i = 0; i < Capacity(); i++ ) {
            if ( table[i].Empty() )
                continue;
            key_size += zeek::util::pad_size(table[i].key_size);
            if ( ! table[i].value )
                continue;
        }

        int distances[DICT_NUM_DISTANCES];
        int max_distance = 0;
        DistanceStats(max_distance, distances, DICT_NUM_DISTANCES);
        printf(
            "cap %'7d ent %'7d %'-7d load %.2f max_dist %2d key/ent %3d lg "
            "%2d remaps %1d remap_end %4d ",
            Capacity(), Length(), MaxLength(), static_cast<double>(Length()) / (table ? Capacity() : 1), max_distance,
            key_size / (Length() ? Length() : 1), log2_buckets, remaps, remap_end);
        if ( Length() > 0 ) {
            for ( size_t i = 0; i < DICT_NUM_DISTANCES - 1; i++ )
                printf("[%zu]%2d%% ", i, 100 * distances[i] / Length());
            printf("[%zu+]%2d%% ", DICT_NUM_DISTANCES - 1, 100 * distances[DICT_NUM_DISTANCES - 1] / Length());
        }
        else
            printf("\n");

        printf("\n");
        if ( level >= 1 ) {
            printf("%-10s %1s %-10s %-4s %-4s %-10s %-18s %-2s\n", "Index", "*", "Bucket", "Dist", "Off", "Hash",
                   "FibHash", "KeySize");
            for ( int i = 0; i < Capacity(); i++ )
                if ( table[i].Empty() )
                    printf("%'10d \n", i);
                else
                    printf("%'10d %1s %'10d %4d %4d 0x%08x 0x%016" PRIx64 "(%3ld) %2d\n", i,
                           (i <= remap_end ? "*" : ""), BucketByPosition(i), table[i].distance,
                           OffsetInClusterByPosition(i), uint(table[i].hash), FibHash(table[i].hash),
                           FibHash(table[i].hash) & 0xFF, table[i].key_size);
        }
    }

    void DistanceStats(int& max_distance, int* distances = nullptr, int num_distances = 0) const {
        max_distance = 0;
        for ( int i = 0; i < num_distances; i++ )
            distances[i] = 0;

        for ( int i = 0; i < Capacity(); i++ ) {
            if ( table[i].Empty() )
                continue;
            if ( table[i].distance > max_distance )
                max_distance = table[i].distance;
            if ( num_distances <= 0 || ! distances )
                continue;
            if ( table[i].distance >= num_distances - 1 )
                distances[num_distances - 1]++;
            else
                distances[table[i].distance]++;
        }
    }

    void DumpKeys() const {
        if ( ! table )
            return;

        char key_file[100];

        int i = 0;
        while ( table[i].Empty() && i < Capacity() )
            i++;

        bool binary = false;
        const char* key = table[i].GetKey();
        for ( int j = 0; j < table[i].key_size; j++ )
            if ( ! isprint(key[j]) ) {
                binary = true;
                break;
            }
        int max_distance = 0;

        DistanceStats(max_distance);
        if ( binary ) {
            char key = static_cast<char>(random() % 26) + 'A';
            snprintf(key_file, 100, "%d.%d-%c.key", Length(), max_distance, key);
            std::ofstream f(key_file, std::ios::binary | std::ios::out | std::ios::trunc);
            for ( int idx = 0; idx < Capacity(); idx++ )
                if ( ! table[idx].Empty() ) {
                    int key_size = table[idx].key_size;
                    f.write(reinterpret_cast<const char*>(&key_size), sizeof(int));
                    f.write(table[idx].GetKey(), table[idx].key_size);
                }
        }
        else {
            char key = static_cast<char>(random() % 26) + 'A';
            snprintf(key_file, 100, "%d.%d-%d.ckey", Length(), max_distance, key);
            std::ofstream f(key_file, std::ios::out | std::ios::trunc);
            for ( int idx = 0; idx < Capacity(); idx++ )
                if ( ! table[idx].Empty() ) {
                    std::string s{table[idx].GetKey(), table[idx].key_size};
                    f << s << "\n";
                }
            f << std::flush;
        }
    }


    using value_type = detail::DictEntry<T>;
    using pointer = detail::DictEntry<T>*;
    using const_pointer = const detail::DictEntry<T>*;


    using iterator = DictIterator<T>;
    using const_iterator = const iterator;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    iterator begin() {
        if ( IsOrdered() )
            return {this, order->begin()};

        return {this, table, table + Capacity()};
    }
    iterator end() {
        if ( IsOrdered() )
            return {this, order->end()};

        return {this, table + Capacity(), table + Capacity()};
    }
    const_iterator begin() const {
        if ( IsOrdered() )
            return {this, order->begin()};

        return {this, table, table + Capacity()};
    }
    const_iterator end() const {
        if ( IsOrdered() )
            return {this, order->end()};

        return {this, table + Capacity(), table + Capacity()};
    }
    const_iterator cbegin() {
        if ( IsOrdered() )
            return {this, order->begin()};

        return {this, table, table + Capacity()};
    }
    const_iterator cend() {
        if ( IsOrdered() )
            return {this, order->end()};

        return {this, table + Capacity(), table + Capacity()};
    }

    RobustDictIterator<T> begin_robust() { return MakeRobustIterator(); }
    RobustDictIterator<T> end_robust() { return RobustDictIterator<T>(); }

private:
    friend zeek::DictIterator<T>;
    friend zeek::RobustDictIterator<T>;

    void SetLog2Buckets(int value) {
        log2_buckets = value;
        bucket_count = 1 << log2_buckets;
        bucket_capacity = (1 << log2_buckets) + log2_buckets;
    }


    int Buckets() const { return table ? bucket_count : 0; }


    uint32_t ThresholdEntries() const {




        int capacity = Capacity();
        if ( log2_buckets <= detail::DICT_THRESHOLD_BITS )
            return capacity;
        return capacity * detail::DICT_LOAD_FACTOR_100 / 100;
    }


    detail::hash_t FibHash(detail::hash_t h) const {


        h &= detail::HASH_MASK;
        h *= 11400714819323198485llu;
        return h;
    }


    int BucketByHash(detail::hash_t h, int bit) const {
        ASSERT(bit >= 0);
        if ( ! bit )
            return 0;

#ifdef DICT_NO_FIB_HASH
        detail::hash_t hash = h;
#else
        detail::hash_t hash = FibHash(h);
#endif

        int m = 64 - bit;
        hash <<= m;
        hash >>= m;

        return hash;
    }


    int BucketByPosition(int position) const {
        ASSERT(table && position >= 0 && position < Capacity() && ! table[position].Empty());
        return position - table[position].distance;
    }




    int EndOfClusterByBucket(int bucket) const {
        ASSERT(bucket >= 0 && bucket < Buckets());
        int i = bucket;
        int current_cap = Capacity();
        while ( i < current_cap && ! table[i].Empty() && BucketByPosition(i) <= bucket )
            i++;
        return i;
    }


    int HeadOfClusterByPosition(int position) const {

        ASSERT(0 <= position && position < Capacity() && ! table[position].Empty());


        int bucket = BucketByPosition(position);
        int i = position;
        while ( i >= bucket && BucketByPosition(i) == bucket )
            i--;

        return i == bucket ? i : i + 1;
    }


    int TailOfClusterByPosition(int position) const {
        ASSERT(0 <= position && position < Capacity() && ! table[position].Empty());

        int bucket = BucketByPosition(position);
        int i = position;
        int current_cap = Capacity();
        while ( i < current_cap && ! table[i].Empty() && BucketByPosition(i) == bucket )
            i++;

        return i - 1;
    }




    int EndOfClusterByPosition(int position) const { return TailOfClusterByPosition(position) + 1; }



    int OffsetInClusterByPosition(int position) const {
        ASSERT(0 <= position && position < Capacity() && ! table[position].Empty());
        int head = HeadOfClusterByPosition(position);
        return position - head;
    }


    int Next(int position) const {
        ASSERT(table && -1 <= position && position < Capacity());

        int current_cap = Capacity();
        do {
            position++;
        } while ( position < current_cap && table[position].Empty() );

        return position;
    }

    void Init() {
        ASSERT(! table);
        table = reinterpret_cast<detail::DictEntry<T>*>(malloc(sizeof(detail::DictEntry<T>) * ExpectedCapacity()));
        for ( int i = Capacity() - 1; i >= 0; i-- )
            table[i].SetEmpty();
    }


    int LinearLookupIndex(const void* key, int key_size, detail::hash_t hash) const {
        auto current_cap = Capacity();
        for ( int i = 0; i < current_cap; i++ )
            if ( ! table[i].Empty() && table[i].Equal(reinterpret_cast<const char*>(key), key_size, hash) )
                return i;
        return -1;
    }



    int LookupIndex(const void* key, int key_size, detail::hash_t hash, int* insert_position = nullptr,
                    int* insert_distance = nullptr) {
        ASSERT_VALID(this);
        if ( ! table )
            return -1;

        int bucket = BucketByHash(hash, log2_buckets);
#ifdef ZEEK_DICT_DEBUG
        int linear_position = LinearLookupIndex(key, key_size, hash);
#endif
        int position = LookupIndex(key, key_size, hash, bucket, Capacity(), insert_position, insert_distance);
        if ( position >= 0 ) {
            ASSERT_EQUAL(position, linear_position);
            return position;
        }

        for ( int i = 1; i <= remaps; i++ ) {
            int prev_bucket = BucketByHash(hash, log2_buckets - i);
            if ( prev_bucket <= remap_end ) {


                position = LookupIndex(key, key_size, hash, prev_bucket, remap_end + 1);
                if ( position >= 0 ) {
                    ASSERT_EQUAL(position, linear_position);

                    if ( ! num_iterators ) {
                        Remap(position, &position);
                        ASSERT_EQUAL(position, LookupIndex(key, key_size, hash));
                    }
                    return position;
                }
            }
        }

#ifdef ZEEK_DICT_DEBUG
        if ( linear_position >= 0 ) {
            ASSERT(false);

            LookupIndex(key, key_size, hash);
        }
#endif
        return -1;
    }





    int LookupIndex(const void* key, int key_size, detail::hash_t hash, int begin, int end,
                    int* insert_position = nullptr, int* insert_distance = nullptr) {
        ASSERT(begin >= 0 && begin < Buckets());
        int i = begin;
        for ( ; i < end && ! table[i].Empty() && BucketByPosition(i) <= begin; i++ )
            if ( BucketByPosition(i) == begin && table[i].Equal(reinterpret_cast<const char*>(key), key_size, hash) )
                return i;


        if ( insert_position )
            *insert_position = i;

        if ( insert_distance ) {
            *insert_distance = i - begin;

            if ( *insert_distance >= detail::TOO_FAR_TO_REACH )
                reporter->FatalErrorWithCore("Dictionary (size %d) insertion distance too far: %d", Length(),
                                             *insert_distance);
        }

        return -1;
    }


    void InsertRelocateAndAdjust(detail::DictEntry<T>& entry, int insert_position) {

#ifdef ZEEK_DICT_DEBUG
        entry.bucket = BucketByHash(entry.hash, log2_buckets);
#endif
        int last_affected_position = insert_position;
        InsertAndRelocate(entry, insert_position, &last_affected_position);
        space_distance_sum += last_affected_position - insert_position;
        space_distance_samples++;



        if ( Remapping() && insert_position <= remap_end &&
             remap_end < last_affected_position ) {



            remap_end = last_affected_position;
        }

        if ( iterators && ! iterators->empty() )
            for ( auto c : *iterators )
                AdjustOnInsert(c, entry, insert_position, last_affected_position);
    }


    void InsertAndRelocate(
        detail::DictEntry<T>& entry, int insert_position,
        int* last_affected_position = nullptr) {
        while ( true ) {
            if ( insert_position >= Capacity() ) {
                ASSERT(insert_position == Capacity());
                SizeUp();

                table[insert_position] = entry;
                if ( last_affected_position )
                    *last_affected_position = insert_position;
                return;
            }
            if ( table[insert_position].Empty() ) {
                table[insert_position] = entry;
                if ( last_affected_position )
                    *last_affected_position = insert_position;
                return;
            }


            auto t = table[insert_position];
            int next = EndOfClusterByPosition(insert_position);
            t.distance += next - insert_position;


            table[insert_position] = entry;
            entry = t;
            insert_position = next;
        }
    }


    void AdjustOnInsert(RobustDictIterator<T>* c, const detail::DictEntry<T>& entry, int insert_position,
                        int last_affected_position) {

        c->inserted->erase(std::remove(c->inserted->begin(), c->inserted->end(), entry), c->inserted->end());
        c->visited->erase(std::remove(c->visited->begin(), c->visited->end(), entry), c->visited->end());

        if ( insert_position < c->next )
            c->inserted->push_back(entry);
        if ( insert_position < c->next && c->next <= last_affected_position ) {
            int k = TailOfClusterByPosition(c->next);
            ASSERT(k >= 0 && k < Capacity());
            c->visited->push_back(table[k]);
        }
    }


    detail::DictEntry<T> RemoveRelocateAndAdjust(int position) {
        int last_affected_position = position;
        detail::DictEntry<T> entry = RemoveAndRelocate(position, &last_affected_position);

#ifdef ZEEK_DICT_DEBUG

        for ( int k = position; k < last_affected_position; k++ )
            ASSERT(! table[k].Empty());
#endif

        if ( iterators && ! iterators->empty() )
            for ( auto c : *iterators )
                AdjustOnRemove(c, entry, position, last_affected_position);

        return entry;
    }


    detail::DictEntry<T> RemoveAndRelocate(int position, int* last_affected_position = nullptr) {

        ASSERT(position >= 0 && position < Capacity() && ! table[position].Empty());

        detail::DictEntry<T> entry = table[position];
        while ( true ) {
            if ( position == Capacity() - 1 || table[position + 1].Empty() || table[position + 1].distance == 0 ) {


                table[position].SetEmpty();
                if ( last_affected_position )
                    *last_affected_position = position;
                return entry;
            }
            int next = TailOfClusterByPosition(position + 1);
            table[position] = table[next];
            table[position].distance -= next - position;
            position = next;
        }

        return entry;
    }


    void AdjustOnRemove(RobustDictIterator<T>* c, const detail::DictEntry<T>& entry, int position,
                        int last_affected_position) {

        c->inserted->erase(std::remove(c->inserted->begin(), c->inserted->end(), entry), c->inserted->end());
        c->visited->erase(std::remove(c->visited->begin(), c->visited->end(), entry), c->visited->end());

        if ( position < c->next && c->next <= last_affected_position ) {
            int moved = HeadOfClusterByPosition(c->next - 1);
            if ( moved < position )
                moved = position;
            c->inserted->push_back(table[moved]);
        }


        if ( c->next < Capacity() && table[c->next].Empty() )
            c->next = Next(c->next);

        if ( c->curr == entry ) {
            if ( c->next >= 0 && c->next < Capacity() && ! table[c->next].Empty() )
                c->curr = table[c->next];
            else
                c->curr = detail::DictEntry<T>(nullptr);
        }
    }

    bool Remapping() const { return remap_end >= 0; }


    void Remap() {






        if ( num_iterators > 0 )
            return;

        int left = detail::DICT_REMAP_ENTRIES;
        while ( remap_end >= 0 && left > 0 ) {
            if ( ! table[remap_end].Empty() && Remap(remap_end) )
                left--;
            else


                remap_end--;
        }
        if ( remap_end < 0 )
            remaps = 0;
    }




    bool Remap(int position, int* new_position = nullptr) {
        ASSERT_VALID(this);


        ASSERT(! iterators || iterators->empty());
        int current = BucketByPosition(position);
        int expected = BucketByHash(table[position].hash, log2_buckets);



        if ( current == expected )
            return false;
        detail::DictEntry<T> entry =
            RemoveAndRelocate(position);
#ifdef ZEEK_DICT_DEBUG
        entry.bucket = expected;
#endif


        int insert_position = EndOfClusterByBucket(expected);
        if ( new_position )
            *new_position = insert_position;
        entry.distance = insert_position - expected;
        InsertAndRelocate(entry,
                          insert_position);
        ASSERT_VALID(this);
        return true;
    }

    void SizeUp() {
        int prev_capacity = Capacity();
        SetLog2Buckets(log2_buckets + 1);

        int capacity = Capacity();
        table = static_cast<detail::DictEntry<T>*>(util::safe_realloc(table, capacity * sizeof(detail::DictEntry<T>)));
        for ( int i = prev_capacity; i < capacity; i++ )
            table[i].SetEmpty();



        if ( iterators && ! iterators->empty() ) {
            for ( auto c : *iterators ) {
                if ( c->next >= prev_capacity )
                    c->next = capacity;
            }
        }





        remap_end = prev_capacity;


        remaps++;
        ASSERT(remaps <= log2_buckets);


        space_distance_sum = 0;
        space_distance_samples = 0;
    }







    detail::DictEntry<T>* LookupEntry(const detail::HashKey& key) {
        return LookupEntry(key.Key(), key.Size(), key.Hash());
    }









    detail::DictEntry<T>* LookupEntry(const void* key, int key_size, detail::hash_t h) const {



        Dictionary* d = const_cast<Dictionary*>(this);
        int position = d->LookupIndex(key, key_size, h);
        return position >= 0 ? &(table[position]) : nullptr;
    }

    bool HaveOnlyRobustIterators() const {
        return (num_iterators == 0) || ((iterators ? iterators->size() : 0) == num_iterators);
    }

    RobustDictIterator<T> MakeRobustIterator() {
        if ( IsOrdered() )
            reporter->InternalError("RobustIterators are not currently supported for ordered dictionaries");

        if ( ! iterators )
            iterators = new std::vector<RobustDictIterator<T>*>;

        return {this};
    }

    detail::DictEntry<T> GetNextRobustIteration(RobustDictIterator<T>* iter) {


        if ( ! table ) {
            iter->Complete();
            return detail::DictEntry<T>(nullptr);
        }




        if ( iter->inserted && ! iter->inserted->empty() ) {


            detail::DictEntry<T> e = iter->inserted->back();
            iter->inserted->pop_back();
            return e;
        }


        if ( iter->next < 0 )
            iter->next = Next(-1);

        if ( iter->next < Capacity() && table[iter->next].Empty() ) {
            iter->next = Next(iter->next);
            ASSERT(iter->next == Capacity());
        }


        int capacity = Capacity();
        if ( iter->visited && ! iter->visited->empty() )

            while ( iter->next < capacity ) {
                ASSERT(! table[iter->next].Empty());
                auto it = std::ranges::find(*iter->visited, table[iter->next]);
                if ( it == iter->visited->end() )
                    break;
                iter->visited->erase(it);
                iter->next = Next(iter->next);
            }

        if ( iter->next >= capacity ) {
            iter->Complete();
            return detail::DictEntry<T>(nullptr);
        }

        ASSERT(! table[iter->next].Empty());
        detail::DictEntry<T> e = table[iter->next];


        iter->next = Next(iter->next);
        return e;
    }

    void IncrIters() { ++num_iterators; }
    void DecrIters() { --num_iterators; }







    uint16_t remaps = 0;
    uint16_t log2_buckets = 0;
    uint32_t bucket_capacity = 1;
    uint32_t bucket_count = 1;



    uint16_t num_iterators = 0;


    int32_t remap_end = -1;

    uint32_t num_entries = 0;
    uint32_t max_entries = 0;
    uint64_t cum_entries = 0;
    uint32_t space_distance_samples = 0;

    int64_t space_distance_sum = 0;

    dict_delete_func delete_func = nullptr;
    detail::DictEntry<T>* table = nullptr;
    std::vector<RobustDictIterator<T>*>* iterators = nullptr;




    std::unique_ptr<detail::DictEntryVec> order;
};

template<typename T>
using PDict = Dictionary<T>;

}
