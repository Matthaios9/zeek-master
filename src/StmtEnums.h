

#pragma once

#include <cstdint>

namespace zeek::detail {


enum StmtTag : uint8_t {
    STMT_ALARM,
    STMT_PRINT,
    STMT_EVENT,
    STMT_EXPR,
    STMT_IF,
    STMT_WHEN,
    STMT_SWITCH,
    STMT_FOR,
    STMT_NEXT,
    STMT_BREAK,
    STMT_RETURN,
    STMT_LIST,
    STMT_EVENT_BODY_LIST,
    STMT_INIT,
    STMT_FALLTHROUGH,
    STMT_WHILE,
    STMT_CATCH_RETURN,
    STMT_CHECK_ANY_LEN,
    STMT_CPP,
    STMT_ZAM,
    STMT_NULL,
    STMT_ASSERT,
    STMT_EXTERN,
    STMT_STD_FUNCTION,
#define NUM_STMTS (int(STMT_STD_FUNCTION) + 1)
};

enum StmtFlowType : uint8_t {
    FLOW_NEXT,
    FLOW_LOOP,
    FLOW_BREAK,
    FLOW_RETURN,
    FLOW_FALLTHROUGH
};

extern const char* stmt_name(StmtTag t);

}
