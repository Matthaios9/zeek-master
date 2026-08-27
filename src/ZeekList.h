

#pragma once

#include "zeek/List.h"

namespace zeek {
namespace detail {

class Expr;
class ID;
class Stmt;
class Attr;
class Timer;

}

class Val;
class Type;

using ValPList = PList<Val>;
using ExprPList = PList<detail::Expr>;
using TypePList = PList<Type>;
using AttrPList = PList<detail::Attr>;
using TimerPList = PList<detail::Timer, ListOrder::UNORDERED>;

}
