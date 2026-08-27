








#pragma once

#include <memory>
#include <string>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/script_opt/ZAM/Profile.h"
#include "zeek/util-types.h"

namespace zeek {

class Connection;
class EnumVal;
class RecordVal;
class StringVal;
class Type;
class Val;

using ValPtr = IntrusivePtr<Val>;
using StringValPtr = IntrusivePtr<StringVal>;
using TypePtr = IntrusivePtr<Type>;

namespace plugin {
class Component;
}

namespace detail {

class Expr;
class Stmt;

using ValVec = std::vector<ValPtr>;

namespace ZAM {



extern std::string curr_func;


extern std::shared_ptr<ZAMLocInfo> curr_loc;



extern TypePtr log_ID_enum_type;


extern TypePtr any_base_type;


bool log_mgr_write(EnumVal* v, RecordVal* r);


size_t broker_mgr_flush_log_buffers();


zeek::Connection* session_mgr_find_connection(Val* cid);


StringVal* analyzer_name(zeek::EnumVal* v);


plugin::Component* analyzer_mgr_lookup(EnumVal* v);






zeek_uint_t conn_size_get_bytes_threshold(Val* cid, bool is_orig);
bool conn_size_set_bytes_threshold(zeek_uint_t threshold, Val* cid, bool is_orig);



void file_mgr_set_handle(StringVal* h);
bool file_mgr_add_analyzer(StringVal* file_id, EnumVal* tag, RecordVal* args);
bool file_mgr_remove_analyzer(StringVal* file_id, EnumVal* tag, RecordVal* args);
bool file_mgr_analyzer_enabled(EnumVal* v);
zeek::StringVal* file_mgr_analyzer_name(EnumVal* v);
bool file_mgr_enable_reassembly(StringVal* file_id);
bool file_mgr_disable_reassembly(StringVal* file_id);
bool file_mgr_set_reassembly_buffer(StringVal* file_id, uint64_t max);

}



class ProfileFunc;
extern bool is_ZAM_compilable(const ProfileFunc* pf, const char** reason = nullptr);


extern bool IsAny(const Type* t);


inline bool IsAny(const TypePtr& t) { return IsAny(t.get()); }



extern bool CheckAnyType(const TypePtr& any_type, const TypePtr& expected_type, const std::shared_ptr<ZAMLocInfo>& loc);

extern void ZAM_run_time_error(const char* msg);
extern void ZAM_run_time_error(const std::shared_ptr<ZAMLocInfo>& loc, const char* msg);
extern void ZAM_run_time_error(const std::shared_ptr<ZAMLocInfo>& loc, const char* msg, const Obj* o);
extern void ZAM_run_time_error(const Stmt* stmt, const char* msg);
extern void ZAM_run_time_error(const char* msg, const Obj* o);

extern bool ZAM_error;

extern void ZAM_run_time_warning(const std::shared_ptr<ZAMLocInfo>& loc, const char* msg);

extern StringVal* ZAM_to_lower(const StringVal* sv);
extern StringVal* ZAM_sub_bytes(const StringVal* s, zeek_uint_t start, zeek_int_t n);

extern StringValPtr ZAM_val_cat(const ValPtr& v);

}
}
