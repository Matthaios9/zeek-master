



#pragma once

#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {


inline std::string Fmt(int i) { return std::to_string(i); }
inline std::string Fmt(p_hash_type u) { return std::to_string(u) + "ULL"; }
extern std::string Fmt(double d);


extern std::string scope_prefix(const std::string& scope);


extern std::string scope_prefix(int scope);




extern bool is_CPP_compilable(const ProfileFunc* pf, const char** reason = nullptr);



extern void lock_file(const std::string& fname, FILE* f);
extern void unlock_file(const std::string& fname, FILE* f);



extern std::string CPPEscape(const char* b, int len);
inline std::string CPPEscape(const char* s) { return CPPEscape(s, strlen(s)); }

}
