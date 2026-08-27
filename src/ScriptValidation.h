
#pragma once

namespace zeek::detail {

class Stmt;





void script_validation();








bool script_is_valid(const Stmt* s, bool is_in_hook);

}
