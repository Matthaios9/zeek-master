

#pragma once

#include <cstdio>

namespace zeek::detail {

class CCL;

class EquivClass {
public:
    explicit EquivClass(int size);
    ~EquivClass();

    void UniqueChar(int sym);
    void CCL_Use(CCL* ccl);



    int BuildECs();

    void ConvertCCL(CCL* ccl);

    bool IsRep(int sym) const { return rep[sym] == sym; }
    int EquivRep(int sym) const { return rep[sym]; }
    int SymEquivClass(int sym) const { return equiv_class[sym]; }
    int* EquivClasses() const { return equiv_class; }

    int NumSyms() const { return size; }
    int NumClasses() const { return num_ecs; }

    void Dump(FILE* f);
    int Size() const;

protected:
    int size;
    int num_ecs;
    int* fwd;
    int* bck;
    int* equiv_class;
    int* rep;
    int* ccl_flags;
    int ec_nil, no_class, no_rep;
};

}
