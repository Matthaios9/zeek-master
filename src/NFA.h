

#pragma once

#include "zeek/List.h"
#include "zeek/Obj.h"

constexpr int NO_ACCEPT = 0;

constexpr int NO_UPPER_BOUND = -1;

constexpr int SYM_BOL = 256;
constexpr int SYM_EOL = 257;
constexpr int NUM_SYM = 258;

constexpr int SYM_EPSILON = 259;
constexpr int SYM_CCL = 260;

namespace zeek {

class Func;

namespace detail {

class CCL;
class EquivClass;

class NFA_State;
using NFA_state_list = PList<NFA_State>;

class NFA_State : public Obj {
public:
    NFA_State(int sym, EquivClass* ec);
    explicit NFA_State(CCL* ccl);
    ~NFA_State() override;

    static void StartNewNFA() { nfa_state_id = 0; }

    void AddXtion(NFA_State* next_state) { xtions.push_back(next_state); }
    NFA_state_list* Transitions() { return &xtions; }
    void AddXtionsTo(NFA_state_list* ns);

    void SetAccept(int accept_val) { accept = accept_val; }
    int Accept() const { return accept; }




    NFA_State* DeepCopy();

    void SetMark(NFA_State* m) { mark = m; }
    NFA_State* Mark() const { return mark; }
    void ClearMarks();

    void SetFirstTransIsBackRef() { first_trans_is_back_ref = true; }

    int TransSym() const { return sym; }
    CCL* TransCCL() const { return ccl; }
    int ID() const { return id; }

    NFA_state_list* EpsilonClosure();

    void Describe(ODesc* d) const override;
    void Dump(FILE* f);

protected:
    int sym;
    int id;
    CCL* ccl;
    int accept;

    static int nfa_state_id;



    bool first_trans_is_back_ref;

    NFA_state_list xtions;
    NFA_state_list* epsclosure;
    NFA_State* mark;
};

class EpsilonState : public NFA_State {
public:
    EpsilonState() : NFA_State(SYM_EPSILON, nullptr) {}
};

class NFA_Machine : public Obj {
public:
    explicit NFA_Machine(NFA_State* first, NFA_State* final = nullptr);
    ~NFA_Machine() override;

    NFA_State* FirstState() const { return first_state; }

    void SetFinalState(NFA_State* final) { final_state = final; }
    NFA_State* FinalState() const { return final_state; }

    void AddAccept(int accept_val);

    void MakeClosure() {
        MakePositiveClosure();
        MakeOptional();
    }
    void MakeOptional();
    void MakePositiveClosure();


    void MakeRepl(int lower, int upper);

    void MarkBOL() { bol = 1; }
    void MarkEOL() { eol = 1; }

    NFA_Machine* DuplicateMachine();
    void LinkCopies(int n);
    void InsertEpsilon();
    void AppendEpsilon();

    void AppendState(NFA_State* new_state);
    void AppendMachine(NFA_Machine* new_mach);

    void Describe(ODesc* d) const override;
    void Dump(FILE* f);

protected:
    NFA_State* first_state;
    NFA_State* final_state;
    int bol, eol;
};

extern NFA_Machine* make_alternate(NFA_Machine* m1, NFA_Machine* m2);






extern NFA_state_list* epsilon_closure(NFA_state_list* states);


extern bool NFA_state_cmp_neg(const NFA_State* v1, const NFA_State* v2);

}
}
