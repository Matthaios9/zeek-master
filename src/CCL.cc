

#include "zeek/CCL.h"

#include <algorithm>

#include "zeek/NFA.h"
#include "zeek/RE.h"

namespace zeek::detail {

CCL::CCL() {
    syms = new int_list;
    index = -(rem->InsertCCL(this) + 1);
    negated = 0;
}

CCL::~CCL() { delete syms; }

void CCL::Negate() {
    negated = 1;
    Add(SYM_BOL);
    Add(SYM_EOL);
}

void CCL::Add(int sym) {
    auto sym_p = static_cast<std::intptr_t>(sym);


    for ( auto sym_entry : *syms )
        if ( sym_entry == sym_p )
            return;

    syms->push_back(sym_p);
}

void CCL::Sort() { std::ranges::sort(*syms); }

}
