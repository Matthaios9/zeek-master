

#ifndef binpac_regex_h
#define binpac_regex_h

#include <vector>

#include "zeek/RE.h"

#include "binpac.h"

namespace zeek {
class RE_Matcher;
}

namespace binpac {






inline void init(FlowBuffer::Policy* fbp = nullptr);


extern std::vector<zeek::RE_Matcher*>* uncompiled_re_matchers;

class RegExMatcher {
public:
    RegExMatcher(const char* pattern) : pattern_(pattern) {
        if ( ! uncompiled_re_matchers )
            uncompiled_re_matchers = new std::vector<zeek::RE_Matcher*>;

        re_matcher_ = new zeek::RE_Matcher(pattern_.c_str());
        uncompiled_re_matchers->push_back(re_matcher_);
    }

    ~RegExMatcher() { delete re_matcher_; }


    int MatchPrefix(const_byteptr data, int len) { return re_matcher_->MatchPrefix(data, len); }

private:
    friend void ::binpac::init(FlowBuffer::Policy*);


    static void init();

    string pattern_;
    zeek::RE_Matcher* re_matcher_;
};

inline void RegExMatcher::init() {
    if ( ! uncompiled_re_matchers )
        return;

    for ( const auto& matcher : *uncompiled_re_matchers ) {
        if ( ! matcher->Compile() ) {
            fprintf(stderr, "binpac: cannot compile regular expression\n");
            exit(1);
        }
    }

    uncompiled_re_matchers->clear();
}

inline void init(FlowBuffer::Policy* fbp) {
    RegExMatcher::init();

    if ( fbp )
        FlowBuffer::init(*fbp);
}

}

#endif
