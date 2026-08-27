

#include "zeek/EquivClass.h"

#include "zeek/CCL.h"
#include "zeek/util.h"

namespace zeek::detail {

EquivClass::EquivClass(int arg_size) {
    size = arg_size;
    fwd = new int[size];
    bck = new int[size];
    equiv_class = new int[size];
    rep = new int[size];
    ccl_flags = nullptr;
    num_ecs = 0;

    ec_nil = no_class = no_rep = size + 1;

    bck[0] = ec_nil;
    fwd[size - 1] = ec_nil;

    for ( int i = 0; i < size; ++i ) {
        if ( i > 0 ) {
            fwd[i - 1] = i;
            bck[i] = i - 1;
        }

        equiv_class[i] = no_class;
        rep[i] = no_rep;
    }
}

EquivClass::~EquivClass() {
    delete[] fwd;
    delete[] bck;
    delete[] equiv_class;
    delete[] rep;
    delete[] ccl_flags;
}

void EquivClass::ConvertCCL(CCL* ccl) {






    int_list* c_syms = ccl->Syms();
    int_list* new_syms = new int_list;

    for ( auto sym : *c_syms ) {
        if ( IsRep(sym) )
            new_syms->push_back(SymEquivClass(sym));
    }

    ccl->ReplaceSyms(new_syms);
}

int EquivClass::BuildECs() {



    for ( int i = 0; i < size; ++i )
        if ( bck[i] == ec_nil ) {
            equiv_class[i] = num_ecs++;
            rep[i] = i;
            for ( int j = fwd[i]; j != ec_nil; j = fwd[j] ) {
                equiv_class[j] = equiv_class[i];
                rep[j] = i;
            }
        }

    return num_ecs;
}

void EquivClass::CCL_Use(CCL* ccl) {



    if ( ! ccl_flags ) {
        ccl_flags = new int[size];
        for ( int i = 0; i < size; ++i )
            ccl_flags[i] = 0;
    }

    int_list* csyms = ccl->Syms();
    for ( size_t i = 0; i < csyms->size();  ) {
        int sym = (*csyms)[i];

        int old_ec = bck[sym];
        int new_ec = sym;

        size_t j = i + 1;

        for ( int k = fwd[sym]; k && k < size; k = fwd[k] ) {
            for ( ; j < csyms->size(); ++j ) {
                if ( (*csyms)[j] > k )


                    break;

                if ( (*csyms)[j] == k && ! ccl_flags[j] ) {




                    bck[k] = new_ec;
                    fwd[new_ec] = k;
                    new_ec = k;


                    ccl_flags[j] = 1;


                    break;
                }
            }

            if ( j < csyms->size() && (*csyms)[j] == k )


                continue;



            bck[k] = old_ec;
            if ( old_ec != ec_nil )
                fwd[old_ec] = k;

            old_ec = k;
        }

        if ( bck[sym] != ec_nil || old_ec != bck[sym] ) {
            bck[sym] = ec_nil;
            fwd[old_ec] = ec_nil;
        }

        fwd[new_ec] = ec_nil;


        for ( ++i; i < csyms->size() && ccl_flags[i]; ++i )

            ccl_flags[i] = 0;
    }
}

void EquivClass::UniqueChar(int sym) {



    if ( fwd[sym] != ec_nil )
        bck[fwd[sym]] = bck[sym];

    if ( bck[sym] != ec_nil )
        fwd[bck[sym]] = fwd[sym];

    fwd[sym] = ec_nil;
    bck[sym] = ec_nil;
}

void EquivClass::Dump(FILE* f) {
    fprintf(f, "%d symbols in EC yielded %d ecs\n", size, num_ecs);
    for ( int i = 0; i < size; ++i )
        if ( SymEquivClass(i) != 0 )
            fprintf(f, "map %d ('%c') -> %d\n", i, i, SymEquivClass(i));
}

int EquivClass::Size() const { return padded_sizeof(*this) + util::pad_size(sizeof(int) * size * (ccl_flags ? 5 : 4)); }

}
