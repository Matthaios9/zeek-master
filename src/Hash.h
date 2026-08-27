


















#pragma once

#include <cstdlib>

#include "zeek/util-types.h"


#include "zeek/ZeekArgs.h"

namespace zeek {

class String;
class ODesc;

}

namespace zeek::detail {

class Frame;

}

namespace zeek::BifFunc {
zeek::ValPtr md5_hmac_native(zeek::detail::Frame* frame, const zeek::Args*);
zeek::ValPtr sha256_hmac_native(zeek::detail::Frame* frame, const zeek::Args*);
}

namespace zeek::detail {

using hash_t = uint64_t;
using hash64_t = uint64_t;
using hash128_t = uint64_t[2];
using hash256_t = uint64_t[4];

class KeyedHash final {
public:
















    static hash64_t Hash64(const void* bytes, uint64_t size);

















    static void Hash128(const void* bytes, uint64_t size, hash128_t* result);

















    static void Hash256(const void* bytes, uint64_t size, hash256_t* result);




















    static hash64_t StaticHash64(const void* bytes, uint64_t size);




















    static void StaticHash128(const void* bytes, uint64_t size, hash128_t* result);




















    static void StaticHash256(const void* bytes, uint64_t size, hash256_t* result);




    constexpr static int SEED_INIT_SIZE = 20;







    static void InitializeSeeds(const std::array<uint32_t, SEED_INIT_SIZE>& seed_data);






    static void InitializeHmacMd5Seed();






    static bool IsInitialized() { return seeds_initialized; }





    static void InitOptions();

private:

    alignas(32) static uint64_t shared_highwayhash_key[4];


    alignas(32) static uint64_t cluster_highwayhash_key[4];


    alignas(16) static unsigned long long shared_siphash_key[2];

    inline static uint8_t shared_hmac_md5_key[16];

    inline static uint8_t shared_hmac_sha256_key[32];

    inline static uint32_t seed_data[SEED_INIT_SIZE];
    inline static bool seeds_initialized = false;
    inline static bool hmac_md5_seeds_initialized = false;

    friend void util::detail::hmac_md5(size_t size, const unsigned char* bytes, unsigned char digest[16]);
    friend ValPtr BifFunc::md5_hmac_native(zeek::detail::Frame* frame, const Args*);
    friend void util::detail::hmac_sha256(size_t size, const unsigned char* bytes, unsigned char digest[32]);
    friend ValPtr BifFunc::sha256_hmac_native(zeek::detail::Frame* frame, const Args*);
};

enum HashKeyTag : uint8_t { HASH_KEY_INT, HASH_KEY_DOUBLE, HASH_KEY_STRING };

constexpr int NUM_HASH_KEYS = HASH_KEY_STRING + 1;

class HashKey final {
public:
    explicit HashKey() { key_u.u32 = 0; }
    explicit HashKey(bool b);
    explicit HashKey(int i);
    explicit HashKey(zeek_int_t bi);
    explicit HashKey(zeek_uint_t bu);
    explicit HashKey(uint32_t u);
    HashKey(const uint32_t u[], size_t n);
    explicit HashKey(double d);
    explicit HashKey(const void* p);
    explicit HashKey(const char* s);
    explicit HashKey(const String* s);


    HashKey(const void* bytes, size_t size);


    HashKey(const void* key, size_t size, hash_t hash);





    HashKey(const void* key, size_t size, hash_t hash, bool dont_copy);


    HashKey(const HashKey& other);


    HashKey(HashKey&& other) noexcept;


    ~HashKey();





    void* TakeKey();

    const void* Key() const { return key; }
    size_t Size() const { return key_size; }
    hash_t Hash() const;

    static hash_t HashBytes(const void* bytes, size_t size);




    bool IsAllocated() const { return (key != nullptr && key != reinterpret_cast<const char*>(&key_u)); }




    template<typename T>
    void ReserveType(const char* tag) {
        Reserve(tag, sizeof(T), sizeof(T));
    }
    void Reserve(const char* tag, size_t addl_size, size_t alignment = 0);


    void Allocate();






    void Write(const char* tag, bool b);
    void Write(const char* tag, int i, bool align = true);
    void Write(const char* tag, zeek_int_t bi, bool align = true);
    void Write(const char* tag, zeek_uint_t bu, bool align = true);
    void Write(const char* tag, uint32_t u, bool align = true);
    void Write(const char* tag, double d, bool align = true);

    void Write(const char* tag, const void* bytes, size_t n, size_t alignment = 0);



    void SkipWrite(const char* tag, size_t n);


    void AlignWrite(size_t alignment);



    void EnsureWriteSpace(size_t n) const;




    void ResetRead() const { read_size = 0; }




    void Read(const char* tag, bool& b) const;
    void Read(const char* tag, int& i, bool align = true) const;
    void Read(const char* tag, zeek_int_t& bi, bool align = true) const;
    void Read(const char* tag, zeek_uint_t& bu, bool align = true) const;
    void Read(const char* tag, uint32_t& u, bool align = true) const;
    void Read(const char* tag, double& d, bool align = true) const;

    void Read(const char* tag, void* out, size_t n, size_t alignment = 0) const;


    void SkipRead(const char* tag, size_t n) const;
    void AlignRead(size_t alignment) const;
    void EnsureReadSpace(size_t n) const;

    void* KeyAtWrite() { return static_cast<void*>(key + write_size); }
    const void* KeyAtRead() const { return static_cast<void*>(key + read_size); }
    const void* KeyEnd() const { return static_cast<void*>(key + key_size); }

    void Describe(ODesc* d) const;

    bool operator==(const HashKey& other) const;
    bool operator!=(const HashKey& other) const;

    bool Equal(const void* other_key, size_t other_size, hash_t other_hash) const;


    HashKey& operator=(const HashKey& other);


    HashKey& operator=(HashKey&& other) noexcept;

private:
    char* CopyKey(const char* key, size_t size) const;




    void Set(bool b);
    void Set(int i);
    void Set(zeek_int_t bi);
    void Set(zeek_uint_t bu);
    void Set(uint32_t u);
    void Set(double d);
    void Set(const void* p);

    union {
        bool b;
        int i;
        zeek_int_t bi;
        zeek_uint_t bu;
        uint32_t u32;
        double d;
        const void* p;
    } key_u;

    char* key = nullptr;
    mutable hash_t hash = 0;
    size_t key_size = 0;
    bool is_our_dynamic = false;
    size_t write_size = 0;
    mutable size_t read_size = 0;
};

extern void init_hash_function();

}
