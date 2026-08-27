

#pragma once

#include <sys/types.h>
#include <cassert>
#include <map>
#include <string>

#include "zeek/NFA.h"
#include "zeek/Obj.h"
#include "zeek/RE.h"

namespace zeek::detail {

class DFA_State;
class DFA_Machine;



#define DFA_UNCOMPUTED_STATE (-2)
#define DFA_UNCOMPUTED_STATE_PTR (reinterpret_cast<DFA_State*>(DFA_UNCOMPUTED_STATE))

class DFA_State : public Obj {
public:
    DFA_State(int state_num, const EquivClass* ec, NFA_state_list* nfa_states, AcceptingSet* accept);
    ~DFA_State() override;

    int StateNum() const { return state_num; }
    int NFAStateNum() const { return nfa_states->length(); }
    void AddXtion(int sym, DFA_State* next_state);

    inline DFA_State* Xtion(int sym, DFA_Machine* machine);

    const AcceptingSet* Accept() const { return accept; }





    bool IsTerminal() const { return ! has_byte_xtion; }

    void SymPartition(const EquivClass* ec);


    NFA_state_list* SymFollowSet(int ec_sym, const EquivClass* ec);

    void SetMark(DFA_State* m) { mark = m; }
    DFA_State* Mark() const { return mark; }
    void ClearMarks();


    const EquivClass* MetaECs() const { return meta_ec; }

    void Describe(ODesc* d) const override;
    void Dump(FILE* f, DFA_Machine* m);
    void Stats(unsigned int* computed, unsigned int* uncomputed);
    unsigned int Size();

protected:
    friend class DFA_State_Cache;

    DFA_State* ComputeXtion(int sym, DFA_Machine* machine);
    void AppendIfNew(int sym, int_list* sym_list);

    int state_num;
    int num_sym;

    DFA_State** xtions;

    AcceptingSet* accept;
    NFA_state_list* nfa_states;
    EquivClass* meta_ec;
    DFA_State* mark;



    bool has_byte_xtion = false;
};

using DigestStr = std::string;

struct DFA_State_Cache_Stats {

    unsigned int nfa_states;
    unsigned int dfa_states;
    unsigned int computed;
    unsigned int uncomputed;
    unsigned int mem;
    unsigned int hits;
    unsigned int misses;
};

class DFA_State_Cache {
public:
    DFA_State_Cache();
    ~DFA_State_Cache();


    DFA_State* Lookup(const NFA_state_list& nfa_states, DigestStr* digest);


    DFA_State* Insert(DFA_State* state, DigestStr digest);

    int NumEntries() const { return states.size(); }

    using Stats = DFA_State_Cache_Stats;
    void GetStats(Stats* s);

private:
    int hits;
    int misses;


    std::map<DigestStr, DFA_State*> states;
};

class DFA_Machine : public Obj {
public:
    DFA_Machine(NFA_Machine* n, EquivClass* ec);
    ~DFA_Machine() override;

    DFA_State* StartState() const { return start_state; }

    int NumStates() const { return dfa_state_cache->NumEntries(); }

    DFA_State_Cache* Cache() { return dfa_state_cache; }

    int Rep(int sym);

    void Describe(ODesc* d) const override;
    void Dump(FILE* f);

protected:
    friend class DFA_State;
    friend class DFA_State_Cache;

    int state_count;


    bool StateSetToDFA_State(NFA_state_list* state_set, DFA_State*& d, const EquivClass* ec);
    const EquivClass* EC() const { return ec; }

    EquivClass* ec;
    DFA_State* start_state;
    DFA_State_Cache* dfa_state_cache;

    NFA_Machine* nfa;
};

inline DFA_State* DFA_State::Xtion(int sym, DFA_Machine* machine) {
    if ( xtions[sym] == DFA_UNCOMPUTED_STATE_PTR )
        return ComputeXtion(sym, machine);
    else
        return xtions[sym];
}

}
