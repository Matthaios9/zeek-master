





#pragma once

#include <sys/types.h>
#include <cstdint>
#include <cstdio>

#include "zeek/util.h"


constexpr size_t ZEEK_MD5_DIGEST_LENGTH = 16;


constexpr size_t ZEEK_SHA_DIGEST_LENGTH = 20;


constexpr size_t ZEEK_SHA224_DIGEST_LENGTH = 28;


constexpr size_t ZEEK_SHA256_DIGEST_LENGTH = 32;


constexpr size_t ZEEK_SHA384_DIGEST_LENGTH = 48;


constexpr size_t ZEEK_SHA512_DIGEST_LENGTH = 64;



constexpr size_t ZEEK_DIGEST_PRINT_LENGTH = (ZEEK_SHA512_DIGEST_LENGTH * 2) + 1;

namespace zeek::detail {



enum HashAlgorithm : uint8_t {
    Hash_MD5,
    Hash_SHA1,
    Hash_SHA224,
    Hash_SHA256,
    Hash_SHA384,
    Hash_SHA512,
};

inline const char* digest_print(const u_char* digest, size_t n) {
    static char buf[ZEEK_DIGEST_PRINT_LENGTH];
    for ( size_t i = 0; i < n; ++i )
        zeek::util::bytetohex(digest[i], &buf[i * 2]);
    buf[2 * n] = '\0';
    return buf;
}

inline const char* md5_digest_print(const u_char digest[ZEEK_MD5_DIGEST_LENGTH]) {
    return digest_print(digest, ZEEK_MD5_DIGEST_LENGTH);
}

inline const char* sha1_digest_print(const u_char digest[ZEEK_SHA_DIGEST_LENGTH]) {
    return digest_print(digest, ZEEK_SHA_DIGEST_LENGTH);
}

inline const char* sha224_digest_print(const u_char digest[ZEEK_SHA224_DIGEST_LENGTH]) {
    return digest_print(digest, ZEEK_SHA224_DIGEST_LENGTH);
}

inline const char* sha256_digest_print(const u_char digest[ZEEK_SHA256_DIGEST_LENGTH]) {
    return digest_print(digest, ZEEK_SHA256_DIGEST_LENGTH);
}

inline const char* sha384_digest_print(const u_char digest[ZEEK_SHA384_DIGEST_LENGTH]) {
    return digest_print(digest, ZEEK_SHA384_DIGEST_LENGTH);
}

inline const char* sha512_digest_print(const u_char digest[ZEEK_SHA512_DIGEST_LENGTH]) {
    return digest_print(digest, ZEEK_SHA512_DIGEST_LENGTH);
}

struct HashDigestState;




HashDigestState* hash_init(HashAlgorithm alg);




void hash_update(HashDigestState* c, const void* data, unsigned long len);




void hash_final(HashDigestState* c, u_char* md);




void hash_final_no_free(HashDigestState* c, u_char* md);




void hash_state_free(HashDigestState* c);




void hash_copy(HashDigestState* out, const HashDigestState* in);









unsigned char* calculate_digest(HashAlgorithm Alg, const unsigned char* data, uint64_t len, unsigned char* out);

}
