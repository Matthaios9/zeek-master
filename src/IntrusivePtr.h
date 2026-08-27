

#pragma once

#include <functional>
#include <type_traits>
#include <utility>

#include "zeek/Obj.h"

namespace zeek {





struct AdoptRef {};





struct NewRef {};





class OpaqueVal;























template<class T>
class IntrusivePtr {
public:


    using pointer = T*;

    using const_pointer = const T*;

    using element_type = T;

    using reference = T&;

    using const_reference = const T&;



    constexpr IntrusivePtr() noexcept = default;

    constexpr IntrusivePtr(std::nullptr_t) noexcept : IntrusivePtr() {

    }









    constexpr IntrusivePtr(AdoptRef, pointer raw_ptr) noexcept : ptr_(raw_ptr) {}









    IntrusivePtr(NewRef, pointer raw_ptr) noexcept : ptr_(raw_ptr) {
        if ( ptr_ )
            Ref(ptr_);
    }

    IntrusivePtr(IntrusivePtr&& other) noexcept : ptr_(other.release()) {

    }

    IntrusivePtr(const IntrusivePtr& other) noexcept : IntrusivePtr(NewRef{}, other.get()) {}

    template<class U>
        requires std::is_convertible_v<U*, T*>
    IntrusivePtr(IntrusivePtr<U> other) noexcept : ptr_(other.release()) {

    }

    ~IntrusivePtr() {
        if ( ptr_ ) {


            if constexpr ( std::is_same_v<T, OpaqueVal> )
                Unref(reinterpret_cast<zeek::Obj*>(ptr_));
            else
                Unref(ptr_);
        }
    }

    void swap(IntrusivePtr& other) noexcept { std::swap(ptr_, other.ptr_); }

    friend void swap(IntrusivePtr& a, IntrusivePtr& b) noexcept {
        using std::swap;
        swap(a.ptr_, b.ptr_);
    }






    pointer release() noexcept { return std::exchange(ptr_, nullptr); }

    IntrusivePtr& operator=(const IntrusivePtr& other) noexcept {
        IntrusivePtr tmp{other};
        swap(tmp);
        return *this;
    }

    IntrusivePtr& operator=(IntrusivePtr&& other) noexcept {
        swap(other);
        return *this;
    }

    IntrusivePtr& operator=(std::nullptr_t) noexcept {
        reset();
        return *this;
    }

    pointer get() const noexcept { return ptr_; }

    pointer operator->() const noexcept { return ptr_; }

    reference operator*() const noexcept { return *ptr_; }

    bool operator!() const noexcept { return ! ptr_; }

    explicit operator bool() const noexcept { return ptr_ != nullptr; }

    void reset() noexcept {
        if ( ptr_ ) {
            Unref(ptr_);
            ptr_ = nullptr;
        }
    }

    void reset(T* ptr) {
        if ( ptr_ )
            Unref(ptr_);

        if ( ptr )
            Ref(ptr);

        ptr_ = ptr;
    }

private:
    pointer ptr_ = nullptr;
};









template<class T, class... Ts>
IntrusivePtr<T> make_intrusive(Ts&&... args) {

    return {AdoptRef{}, new T(std::forward<Ts>(args)...)};
}







template<class T, class U>
IntrusivePtr<T> cast_intrusive(IntrusivePtr<U> p) noexcept {
    return {AdoptRef{}, static_cast<T*>(p.release())};
}






template<class T>
bool operator==(const zeek::IntrusivePtr<T>& x, std::nullptr_t) {
    return ! x;
}




template<class T>
bool operator==(std::nullptr_t, const zeek::IntrusivePtr<T>& x) {
    return ! x;
}




template<class T>
bool operator!=(const zeek::IntrusivePtr<T>& x, std::nullptr_t) {
    return static_cast<bool>(x);
}




template<class T>
bool operator!=(std::nullptr_t, const zeek::IntrusivePtr<T>& x) {
    return static_cast<bool>(x);
}






template<class T>
bool operator==(const zeek::IntrusivePtr<T>& x, const T* y) {
    return x.get() == y;
}




template<class T>
bool operator==(const T* x, const zeek::IntrusivePtr<T>& y) {
    return x == y.get();
}




template<class T>
bool operator!=(const zeek::IntrusivePtr<T>& x, const T* y) {
    return x.get() != y;
}




template<class T>
bool operator!=(const T* x, const zeek::IntrusivePtr<T>& y) {
    return x != y.get();
}









template<class T, class U>
auto operator==(const zeek::IntrusivePtr<T>& x, const zeek::IntrusivePtr<U>& y) -> decltype(x.get() == y.get()) {
    return x.get() == y.get();
}




template<class T, class U>
auto operator!=(const zeek::IntrusivePtr<T>& x, const zeek::IntrusivePtr<U>& y) -> decltype(x.get() != y.get()) {
    return x.get() != y.get();
}

}



namespace std {
template<class T>

struct hash<zeek::IntrusivePtr<T>> {

    size_t operator()(const zeek::IntrusivePtr<T>& v) const noexcept { return std::hash<T*>{}(v.get()); }
};
}
