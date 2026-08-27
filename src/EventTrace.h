



#pragma once

#include "zeek/zeek-config.h"

#include "zeek/Val.h"
#include "zeek/ZeekArgs.h"

namespace zeek::detail {

class ValTrace;
class ValTraceMgr;



class ValDelta {
public:
    ValDelta(const ValTrace* _vt) : vt(_vt) {}
    virtual ~ValDelta() = default;



    virtual std::string Generate(ValTraceMgr* vtm) const;







    virtual bool NeedsLHS() const { return true; }

    const ValTrace* GetValTrace() const { return vt; }

protected:
    const ValTrace* vt;
};

using DeltaVector = std::vector<std::unique_ptr<ValDelta>>;





class ValTrace {
public:
    ValTrace(ValPtr v);
    ~ValTrace() = default;

    const ValPtr& GetVal() const { return v; }
    const TypePtr& GetType() const { return t; }
    const auto& GetElems() const { return elems; }




    bool operator==(const ValTrace& vt) const;
    bool operator!=(const ValTrace& vt) const { return ! ((*this) == vt); }









    void ComputeDelta(const ValTrace* prev, DeltaVector& deltas) const;

private:

    void TraceList(const ListValPtr& lv);
    void TraceRecord(const RecordValPtr& rv);
    void TraceTable(const TableValPtr& tv);
    void TraceVector(const VectorValPtr& vv);


    bool SameList(const ValTrace& vt) const;
    bool SameRecord(const ValTrace& vt) const;
    bool SameTable(const ValTrace& vt) const;
    bool SameVector(const ValTrace& vt) const;



    bool SameElems(const ValTrace& vt) const;



    bool SameSingleton(const ValTrace& vt) const;



    void ComputeRecordDelta(const ValTrace* prev, DeltaVector& deltas) const;
    void ComputeTableDelta(const ValTrace* prev, DeltaVector& deltas) const;
    void ComputeVectorDelta(const ValTrace* prev, DeltaVector& deltas) const;


    std::vector<std::shared_ptr<ValTrace>> elems;


    std::vector<std::shared_ptr<ValTrace>> elems2;

    ValPtr v;
    TypePtr t;
};


class DeltaReplaceValue : public ValDelta {
public:
    DeltaReplaceValue(const ValTrace* _vt, ValPtr _new_val) : ValDelta(_vt), new_val(std::move(_new_val)) {}

    std::string Generate(ValTraceMgr* vtm) const override;

private:
    ValPtr new_val;
};


class DeltaSetField : public ValDelta {
public:
    DeltaSetField(const ValTrace* _vt, int _field, ValPtr _new_val)
        : ValDelta(_vt), field(_field), new_val(std::move(_new_val)) {}

    std::string Generate(ValTraceMgr* vtm) const override;

private:
    int field;
    ValPtr new_val;
};


class DeltaRemoveField : public ValDelta {
public:
    DeltaRemoveField(const ValTrace* _vt, int _field) : ValDelta(_vt), field(_field) {}

    std::string Generate(ValTraceMgr* vtm) const override;
    bool NeedsLHS() const override { return false; }

private:
    int field;
};


class DeltaRecordCreate : public ValDelta {
public:
    DeltaRecordCreate(const ValTrace* _vt) : ValDelta(_vt) {}

    std::string Generate(ValTraceMgr* vtm) const override;
};



class DeltaSetSetEntry : public ValDelta {
public:
    DeltaSetSetEntry(const ValTrace* _vt, ValPtr _index) : ValDelta(_vt), index(std::move(_index)) {}

    std::string Generate(ValTraceMgr* vtm) const override;
    bool NeedsLHS() const override { return false; }

private:
    ValPtr index;
};




class DeltaSetTableEntry : public ValDelta {
public:
    DeltaSetTableEntry(const ValTrace* _vt, ValPtr _index, ValPtr _new_val)
        : ValDelta(_vt), index(std::move(_index)), new_val(std::move(_new_val)) {}

    std::string Generate(ValTraceMgr* vtm) const override;

private:
    ValPtr index;
    ValPtr new_val;
};


class DeltaRemoveTableEntry : public ValDelta {
public:
    DeltaRemoveTableEntry(const ValTrace* _vt, ValPtr _index) : ValDelta(_vt), index(std::move(_index)) {}

    std::string Generate(ValTraceMgr* vtm) const override;
    bool NeedsLHS() const override { return false; }

private:
    ValPtr index;
};


class DeltaSetCreate : public ValDelta {
public:
    DeltaSetCreate(const ValTrace* _vt) : ValDelta(_vt) {}

    std::string Generate(ValTraceMgr* vtm) const override;
};


class DeltaTableCreate : public ValDelta {
public:
    DeltaTableCreate(const ValTrace* _vt) : ValDelta(_vt) {}

    std::string Generate(ValTraceMgr* vtm) const override;
};


class DeltaVectorSet : public ValDelta {
public:
    DeltaVectorSet(const ValTrace* _vt, int _index, ValPtr _elem)
        : ValDelta(_vt), index(_index), elem(std::move(_elem)) {}

    std::string Generate(ValTraceMgr* vtm) const override;

private:
    int index;
    ValPtr elem;
};


class DeltaVectorAppend : public ValDelta {
public:
    DeltaVectorAppend(const ValTrace* _vt, int _index, ValPtr _elem)
        : ValDelta(_vt), index(_index), elem(std::move(_elem)) {}

    std::string Generate(ValTraceMgr* vtm) const override;

private:
    int index;
    ValPtr elem;
};


class DeltaVectorCreate : public ValDelta {
public:
    DeltaVectorCreate(const ValTrace* _vt) : ValDelta(_vt) {}

    std::string Generate(ValTraceMgr* vtm) const override;
};



class DeltaUnsupportedCreate : public ValDelta {
public:
    DeltaUnsupportedCreate(const ValTrace* _vt) : ValDelta(_vt) {}

    std::string Generate(ValTraceMgr* vtm) const override;
};



class DeltaGen {
public:
    DeltaGen(ValPtr _val, std::string _rhs, bool _needs_lhs, bool _is_first_def)
        : val(std::move(_val)), rhs(std::move(_rhs)), needs_lhs(_needs_lhs), is_first_def(_is_first_def) {}

    const ValPtr& GetVal() const { return val; }
    const std::string& RHS() const { return rhs; }
    bool NeedsLHS() const { return needs_lhs; }
    bool IsFirstDef() const { return is_first_def; }

private:
    ValPtr val;


    std::string rhs;



    bool needs_lhs;



    bool is_first_def;
};

using DeltaGenVec = std::vector<DeltaGen>;


class EventTrace {
public:



    EventTrace(const ScriptFunc* _ev, double _nt, size_t event_num);



    void SetArgs(std::string _args) { args = std::move(_args); }


    void AddDelta(ValPtr val, std::string rhs, bool needs_lhs, bool is_first_def) {
        auto& d = is_post ? post_deltas : deltas;
        d.emplace_back(val, std::move(rhs), needs_lhs, is_first_def);
    }






    void SetDoingPost() { is_post = true; }

    const char* GetName() const { return name.c_str(); }









    void Generate(FILE* f, ValTraceMgr& vtm, const EventTrace* predecessor, const std::string& successor) const;

private:


    void Generate(FILE* f, ValTraceMgr& vtm, const DeltaGenVec& dvec, const std::string& successor,
                  int num_pre = 0) const;

    const ScriptFunc* ev;
    double nt;
    bool is_post = false;



    DeltaGenVec deltas;



    DeltaGenVec post_deltas;


    std::string name;
    std::string args;
};


class ValTraceMgr {
public:

    void TraceEventValues(std::shared_ptr<EventTrace> et, const zeek::Args* args);




    void FinishCurrentEvent(const zeek::Args* args);



    const std::string& ValName(const ValPtr& v);
    const std::string& ValName(const ValTrace* vt) { return ValName(vt->GetVal()); }



    bool IsGlobal(const ValPtr& v) const { return globals.contains(v.get()); }




    double GetBaseTime() const { return base_time; }
    void SetBaseTime(double bt) { base_time = bt; }



    std::string TimeConstant(double t);


    const auto& GetConstants() const { return constants; }

private:

    void AddVal(ValPtr v);


    void NewVal(ValPtr v);




    void ValUsed(const ValPtr& v);



    void AssessChange(const ValTrace* vt, const ValTrace* prev_vt);


    void TrackVar(const Val* vt);


    std::string GenValName(const ValPtr& v);




    bool IsUnspecifiedAggregate(const ValPtr& v) const;


    bool IsUnsupported(const Val* v) const;


    std::unordered_map<const Val*, std::shared_ptr<ValTrace>> val_map;




    std::unordered_map<const Val*, std::string> val_names;
    int num_vars = 0;





    std::unordered_set<const Val*> processed_vals;



    std::unordered_set<const Val*> globals;



    std::array<std::set<std::string>, NUM_TYPES> constants;




    double base_time = 0.0;


    std::shared_ptr<EventTrace> curr_ev;



    std::vector<ValPtr> vals;
};



class EventTraceMgr {
public:
    EventTraceMgr(const std::string& trace_file);

    ~EventTraceMgr();


    void Generate();


    void StartEvent(const ScriptFunc* ev, const zeek::Args* args);


    void EndEvent(const ScriptFunc* ev, const zeek::Args* args);


    void ScriptEventQueued(const EventHandlerPtr& h);

private:
    FILE* f = nullptr;
    ValTraceMgr vtm;


    std::vector<std::shared_ptr<EventTrace>> events;


    std::unordered_set<std::string> script_events;
};


ZEEK_EXTERN_DATA std::unique_ptr<EventTraceMgr> event_trace_mgr;

}
