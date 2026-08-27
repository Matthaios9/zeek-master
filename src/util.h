

#pragma once

#include "zeek/zeek-config.h"



#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

#include <libgen.h>
#include <unistd.h>
#include <concepts>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <ctime>
#elif defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#else
#include <ctime>
#endif

#ifdef DEBUG

#include <cassert>


#ifdef ASSERT
#undef ASSERT
#endif
#define ASSERT(x) assert(x)
#define DEBUG_MSG(...) fprintf(stderr, __VA_ARGS__)
#define DEBUG_fputs fputs

#else
#ifdef MSTCPIP_ASSERT_UNDEFINED
#undef ASSERT
#endif

#define ASSERT(x)
#define DEBUG_MSG(...)
#define DEBUG_fputs(...)

#endif


#ifdef USE_PERFTOOLS_DEBUG
#include <gperftools/heap-checker.h>
#include <gperftools/heap-profiler.h>
extern HeapLeakChecker* heap_checker;
#endif

extern "C" {
#include "zeek/3rdparty/modp_numtoa.h"
}

#ifdef HAVE_LINUX
#include <pthread.h>
#include <sys/prctl.h>
#endif

#ifdef __FreeBSD__
#include <pthread_np.h>
#endif

#ifdef _MSC_VER
#include <pthread.h>
inline constexpr std::string_view path_list_separator = ";";
#else
inline constexpr std::string_view path_list_separator = ":";
#endif

#include "zeek/UID.h"
#include "zeek/util-types.h"

#ifndef HAVE_STRCASESTR
extern char* strcasestr(const char* s, const char* find);
#endif


extern "C" void out_of_memory(const char* where);

[[deprecated("Remove in v9.1. Use zeek::UID_POOL_DEFAULT_INTERNAL instead.")]]
constexpr int UID_POOL_DEFAULT_INTERNAL = zeek::UID_POOL_DEFAULT_INTERNAL;
[[deprecated("Remove in v9.1. Use zeek::UID_POOL_DEFAULT_SCRIPT instead.")]]
constexpr int UID_POOL_DEFAULT_SCRIPT = zeek::UID_POOL_DEFAULT_SCRIPT;
[[deprecated("Remove in v9.1. Use zeek::UID_POOL_CUSTOM_SCRIPT instead.")]]
constexpr int UID_POOL_CUSTOM_SCRIPT = zeek::UID_POOL_CUSTOM_SCRIPT;

namespace zeek {

class ODesc;
class RecordVal;

namespace util {
namespace detail {

std::string extract_ip(const std::string& i);
std::string extract_ip_and_len(const std::string& i, int* len);




extern int expand_escape(const char*& s);

extern const char* fmt_access_time(double time);

extern bool ensure_intermediate_dirs(const char* dirname);
extern bool ensure_dir(const char* dirname);


[[deprecated("Remove in v9.1. Use hmac_sha256.")]]
extern void hmac_md5(size_t size, const unsigned char* bytes, unsigned char digest[16]);


extern void hmac_sha256(size_t size, const unsigned char* bytes, unsigned char digest[32]);








extern void init_random_seed(const char* load_file, const char* write_file, bool use_empty_seeds,
                             const std::string& seed_string = {});




unsigned int initial_seed();


extern bool have_random_seed();









long int prng(long int state);







long int random_number();





long int max_random();







void seed_random(unsigned int seed);







void set_thread_name(const char* name, pthread_t tid = pthread_self());









using SourceID = std::uintptr_t;
constexpr SourceID SOURCE_LOCAL = 0;






constexpr SourceID SOURCE_BROKER = 0xffffffff;

bool is_package_loader(const std::string& path);

extern void add_to_zeek_path(const std::string& dir);








std::string flatten_script_name(const std::string& name, const std::string& prefix = "");







std::string normalize_path(std::string_view path);






std::string without_zeekpath_component(std::string_view path);







std::string get_exe_path(const std::string& invocation);








FILE* open_package(std::string& path, const std::string& mode = "r");


const char* log_file_name(const char* tag);


void terminate_processing();




void set_processing_status(const char* status, const char* reason);




extern FILE* rotate_file(const char* name, RecordVal* rotate_info);







double parse_rotate_base_time(const char* rotate_base_time);








double calc_next_rotate(double current, double rotate_interval, double base);

int setvbuf(FILE* stream, char* buf, int type, size_t size);

}

template<class T>
void delete_each(T* t) {
    using iterator = typename T::iterator;
    for ( iterator it = t->begin(); it != t->end(); ++it )
        delete *it;
}

inline void bytetohex(unsigned char byte, char* hex_out) {
    static constexpr char hex_chars[] = "0123456789abcdef";
    hex_out[0] = hex_chars[(byte & 0xf0) >> 4];
    hex_out[1] = hex_chars[byte & 0x0f];
}

std::string get_unescaped_string(const std::string& str);

ODesc* get_escaped_string(ODesc* d, const char* str, size_t len, bool escape_all);
std::string get_escaped_string(const char* str, size_t len, bool escape_all);

inline std::string get_escaped_string(const std::string& str, bool escape_all) {
    return get_escaped_string(str.data(), str.length(), escape_all);
}

std::vector<std::string>* tokenize_string(std::string_view input, std::string_view delim,
                                          std::vector<std::string>* rval = nullptr, int limit = 0);

std::vector<std::string_view> tokenize_string(std::string_view input, const char delim);

extern char* copy_string(const char* str, size_t len);
extern char* copy_string(const char* s);
extern bool streq(const char* s1, const char* s2);
extern bool starts_with(std::string_view s, std::string_view beginning);
extern bool ends_with(std::string_view s, std::string_view ending);

extern char* skip_whitespace(char* s);
extern const char* skip_whitespace(const char* s);
extern char* skip_whitespace(char* s, char* end_of_s);
extern const char* skip_whitespace(const char* s, const char* end_of_s);
extern char* skip_digits(char* s);
extern char* get_word(char*& s);
extern void get_word(int length, const char* s, int& pwlen, const char*& pw);
extern void to_upper(char* s);
extern std::string to_upper(const std::string& s);
extern int decode_hex(char ch);
extern unsigned char encode_hex(int h);
template<std::integral T>
int atoi_n(int len, const char* s, const char** end, int base, T& result);
extern char* uitoa_n(uint64_t value, char* str, int n, int base, const char* prefix = nullptr);
extern const char* strpbrk_n(size_t len, const char* s, const char* charset);
int strstr_n(const int big_len, const unsigned char* big, const int little_len, const unsigned char* little);


extern std::string strreplace(const std::string& s, const std::string& o, const std::string& n);


extern std::string strstrip(std::string s);


extern std::string strtolower(const std::string& s);


extern std::string strtoupper(const std::string& s);

extern int fputs(int len, const char* s, FILE* fp);
extern bool is_printable(const char* s, int len);

extern const char* fmt_bytes(const char* data, int len);





extern const char* vfmt(const char* format, va_list args);
extern const char* fmt(const char* format, ...) __attribute__((format(printf, 1, 2)));


bool is_dir(const std::string& path);


bool is_file(const std::string& path);

extern int int_list_cmp(const void* v1, const void* v2);

extern const std::string& zeek_path();
extern const char* zeek_plugin_path();
extern const char* zeek_plugin_activate();
extern std::string zeek_prefixes();

std::string implode_string_vector(const std::vector<std::string>& v, const std::string& delim = "\n");








std::string find_file(const std::string& filename, const std::string& path_set, const std::string& opt_ext = "");







std::string find_script_file(const std::string& filename, const std::string& path_set);


FILE* open_file(const std::string& path, const std::string& mode = "r");





extern double current_time(bool real = false);


extern struct timeval double_to_timeval(double t);


extern int time_compare(struct timeval* tv_a, struct timeval* tv_b);


extern double curr_CPU_time();

namespace this_thread {

inline double get_cpu_time() {
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) / 1e9;
}
}






extern uint64_t calculate_unique_id(const size_t pool = zeek::UID_POOL_DEFAULT_INTERNAL);


struct ltstr {
    bool operator()(const char* s1, const char* s2) const { return strcmp(s1, s2) < 0; }
};

constexpr size_t pad_size(size_t size) {


    if ( size == 0 )
        return 0;

    const size_t pad = 8;
    if ( size < 12 )
        return 2 * pad;

    return ((size + 3) / pad + 1) * pad;
}

template<typename T>
constexpr size_t padded_size_of() {
    return zeek::util::pad_size(sizeof(T));
}


#define padded_sizeof(x) (zeek::util::padded_size_of<decltype((x))>())




extern bool safe_write(int fd, const char* data, int len);


extern bool safe_pwrite(int fd, const unsigned char* data, size_t len, size_t offset);



extern bool safe_fsync(int fd);


extern void safe_close(int fd);





inline void* safe_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if ( size && ! new_ptr )
        out_of_memory("realloc");

    return new_ptr;
}

inline void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if ( ! ptr )
        out_of_memory("malloc");

    return ptr;
}

inline char* safe_strncpy(char* dest, const char* src, size_t n) {
    char* result = strncpy(dest, src, n - 1);
    dest[n - 1] = '\0';
    return result;
}



inline bool is_power_of_2(zeek_uint_t x) { return ((x - 1) & x) == 0; }



const void* memory_align(const void* ptr, size_t size);



void* memory_align_and_pad(void* ptr, size_t size);


int memory_size_align(size_t offset, size_t size);



extern void get_memory_usage(uint64_t* total, uint64_t* malloced);




struct CompareString {
    bool operator()(char const* a, char const* b) const { return strcmp(a, b) < 0; }
};







std::string canonify_name(const std::string& name);





void zeek_strerror_r(int zeek_errno, char* buf, size_t buflen);

enum UTF8EscapingFlags : uint8_t {
    ESCAPE_NONE = 0x00,



    ESCAPE_PRINTABLE_CONTROLS = 0x01,

    ESCAPE_UNPRINTABLE_CONTROLS = 0x02,
};










std::string escape_utf8(std::string_view val, int flags);
















std::string escape_string_for_json(std::string_view raw, std::string_view escape_prefix);

[[deprecated("Remove in v9.1. Use escape_utf8 instead.")]]
inline std::string json_escape_utf8(const char* val, size_t val_size, bool escape_printable_controls = true) {
    return escape_utf8(std::string_view{val, val_size},
                       escape_printable_controls ? ESCAPE_NONE : ESCAPE_PRINTABLE_CONTROLS);
}

[[deprecated("Remove in v9.1. Use escape_utf8 instead.")]]
inline std::string json_escape_utf8(const std::string& val, bool escape_printable_controls = true) {
    return escape_utf8(val, escape_printable_controls ? ESCAPE_NONE : ESCAPE_PRINTABLE_CONTROLS);
}








bool approx_equal(double a, double b, double tolerance = std::numeric_limits<double>::epsilon());







template<typename T>
std::vector<T> split(T s, const T& delim) {

    if ( delim.empty() )
        return {std::move(s)};


    if ( s.size() < delim.size() )
        return {std::move(s)};

    std::vector<T> l;

    const bool ends_in_delim = (s.substr(s.size() - delim.size()) == delim);

    do {
        size_t p = s.find(delim);
        l.push_back(s.substr(0, p));
        if ( p == std::string::npos )
            break;

        s = s.substr(p + delim.size());
    } while ( ! s.empty() );

    if ( ends_in_delim )
        l.emplace_back(T{});

    return l;
}











template<typename T, typename U = typename T::value_type*>
std::vector<T> split(T s, U delim) {
    return split(std::move(s), std::move(T{delim}));
}








inline std::vector<std::string_view> split(const char* s, const char* delim) {
    return split(std::string_view(s), std::string_view(delim));
}








inline std::vector<std::wstring_view> split(const wchar_t* s, const wchar_t* delim) {
    return split(std::wstring_view(s), std::wstring_view(delim));
}




size_t double_to_str(double v, char* buf, size_t buf_size, int precision, bool no_exp);

}
}
