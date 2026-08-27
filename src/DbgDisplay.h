



#pragma once

namespace zeek::detail {

class Expr;


class DbgDisplay {
public:
    DbgDisplay(Expr* expr_to_display);

    bool IsEnabled() { return enabled; }
    bool SetEnable(bool do_enable) {
        bool old_value = enabled;
        enabled = do_enable;
        return old_value;
    }

    const Expr* Expression() const { return expression; }

protected:
    bool enabled;
    Expr* expression;
};

}
