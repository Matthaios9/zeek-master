



#pragma once

namespace zeek {
class Obj;
}

namespace zeek::detail {

class Expr;

class DbgWatch {
public:
    explicit DbgWatch(Obj* var_to_watch);
    explicit DbgWatch(Expr* expr_to_watch);
    ~DbgWatch() = default;

protected:
    Obj* var;
    Expr* expr;
};

}
