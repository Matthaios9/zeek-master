

#pragma once




















#include <cassert>
#include <cstdarg>
#include <initializer_list>
#include <iterator>

#include "zeek/util.h"

namespace zeek {

enum class ListOrder : uint8_t { ORDERED, UNORDERED };

template<typename T, ListOrder Order = ListOrder::ORDERED>
class List {
public:
    constexpr static int DEFAULT_LIST_SIZE = 10;
    constexpr static int LIST_GROWTH_FACTOR = 2;

    ~List() { free(static_cast<void*>(entries)); }
    explicit List(int size = 0) {
        num_entries = 0;

        if ( size <= 0 ) {
            max_entries = 0;
            entries = nullptr;
            return;
        }

        max_entries = size;


        entries = reinterpret_cast<T*>(util::safe_malloc(max_entries * sizeof(T)));
    }

    List(const List& b) {
        max_entries = b.max_entries;
        num_entries = b.num_entries;

        if ( max_entries )

            entries = reinterpret_cast<T*>(util::safe_malloc(max_entries * sizeof(T)));
        else
            entries = nullptr;

        for ( int i = 0; i < num_entries; ++i )
            entries[i] = b.entries[i];
    }

    List(List&& b) noexcept {
        entries = b.entries;
        num_entries = b.num_entries;
        max_entries = b.max_entries;

        b.entries = nullptr;
        b.num_entries = b.max_entries = 0;
    }

    List(const T* arr, int n) {
        num_entries = max_entries = n;

        entries = reinterpret_cast<T*>(util::safe_malloc(max_entries * sizeof(T)));

        memcpy(entries, arr, n * sizeof(T));
    }

    List(std::initializer_list<T> il) : List(il.begin(), il.size()) {}

    List& operator=(const List& b) {
        if ( this == &b )
            return *this;

        free(static_cast<void*>(entries));

        max_entries = b.max_entries;
        num_entries = b.num_entries;

        if ( max_entries )

            entries = reinterpret_cast<T*>(util::safe_malloc(max_entries * sizeof(T)));
        else
            entries = nullptr;

        for ( int i = 0; i < num_entries; ++i )
            entries[i] = b.entries[i];

        return *this;
    }

    List& operator=(List&& b) noexcept {
        if ( this == &b )
            return *this;

        free(static_cast<void*>(entries));
        entries = b.entries;
        num_entries = b.num_entries;
        max_entries = b.max_entries;

        b.entries = nullptr;
        b.num_entries = b.max_entries = 0;
        return *this;
    }


    T& operator[](int i) const { return entries[i]; }

    void clear()
    {
        free(static_cast<void*>(entries));
        entries = nullptr;
        num_entries = max_entries = 0;
    }

    bool empty() const noexcept { return num_entries == 0; }
    size_t size() const noexcept { return num_entries; }

    int length() const { return num_entries; }
    int max() const { return max_entries; }
    int resize(int new_size = 0)
    {
        if ( new_size < num_entries )
            new_size = num_entries;

        if ( new_size != max_entries ) {

            entries = reinterpret_cast<T*>(util::safe_realloc(reinterpret_cast<void*>(entries), sizeof(T) * new_size));
            if ( entries )
                max_entries = new_size;
            else
                max_entries = 0;
        }

        return max_entries;
    }

    void push_front(const T& a) {
        if ( num_entries == max_entries )
            resize(max_entries ? max_entries * LIST_GROWTH_FACTOR : DEFAULT_LIST_SIZE);

        for ( int i = num_entries; i > 0; --i )
            entries[i] = entries[i - 1];

        ++num_entries;
        entries[0] = a;
    }

    void push_back(const T& a) {
        if ( num_entries == max_entries )
            resize(max_entries ? max_entries * LIST_GROWTH_FACTOR : DEFAULT_LIST_SIZE);

        entries[num_entries++] = a;
    }

    void pop_front() { remove_nth(0); }
    void pop_back() { remove_nth(num_entries - 1); }

    T& front() { return entries[0]; }
    T& back() { return entries[num_entries - 1]; }



    void append(const T& a)
    {
        push_back(a);
    }

    bool remove(const T& a)
    {
        int pos = member_pos(a);
        if ( pos != -1 ) {
            remove_nth(pos);
            return true;
        }

        return false;
    }

    T remove_nth(int n)
    {
        assert(n >= 0 && n < num_entries);

        T old_ent = entries[n];




        if constexpr ( Order == ListOrder::ORDERED ) {
            --num_entries;

            for ( ; n < num_entries; ++n )
                entries[n] = entries[n + 1];
        }
        else {
            entries[n] = entries[num_entries - 1];
            --num_entries;
        }

        return old_ent;
    }


    bool is_member(const T& a) const {
        int pos = member_pos(a);
        return pos != -1;
    }


    int member_pos(const T& e) const {
        int i;
        for ( i = 0; i < length() && e != entries[i]; ++i )
            ;

        return (i == length()) ? -1 : i;
    }

    T replace(int ent_index, const T& new_ent)
    {
        if ( ent_index < 0 )
            return T{};

        T old_ent{};

        if ( ent_index > num_entries - 1 ) {
            resize(ent_index + 1);

            for ( int i = num_entries; i < max_entries; ++i )
                entries[i] = T{};
            num_entries = max_entries;
        }
        else
            old_ent = entries[ent_index];

        entries[ent_index] = new_ent;

        return old_ent;
    }


    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;


    using iterator = pointer;
    using const_iterator = const_pointer;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    iterator begin() { return entries; }
    iterator end() { return entries + num_entries; }
    const_iterator begin() const { return entries; }
    const_iterator end() const { return entries + num_entries; }
    const_iterator cbegin() const { return entries; }
    const_iterator cend() const { return entries + num_entries; }

    reverse_iterator rbegin() { return reverse_iterator{end()}; }
    reverse_iterator rend() { return reverse_iterator{begin()}; }
    const_reverse_iterator rbegin() const { return const_reverse_iterator{end()}; }
    const_reverse_iterator rend() const { return const_reverse_iterator{begin()}; }
    const_reverse_iterator crbegin() const { return rbegin(); }
    const_reverse_iterator crend() const { return rend(); }

protected:
























    T* entries;
    int max_entries;
    int num_entries;
};


template<typename T, ListOrder Order = ListOrder::ORDERED>
using PList = List<T*, Order>;


using name_list = PList<char>;

}



#define loop_over_list(list, iterator)                                                                                 \
    int iterator;                                                                                                      \
    for ( (iterator) = 0; (iterator) < (list).length(); ++(iterator) )
