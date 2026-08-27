



#include "zeek/DbgWatch.h"

#include "zeek/Debug.h"
#include "zeek/Reporter.h"

namespace zeek::detail {


DbgWatch::DbgWatch(zeek::Obj* var_to_watch) { reporter->InternalError("DbgWatch unimplemented"); }

DbgWatch::DbgWatch(Expr* expr_to_watch) { reporter->InternalError("DbgWatch unimplemented"); }

}
