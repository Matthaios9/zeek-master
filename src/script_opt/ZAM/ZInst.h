



#pragma once

#include "zeek/script_opt/ZAM/Support.h"
#include "zeek/script_opt/ZAM/ZInstAux.h"
#include "zeek/script_opt/ZAM/ZOp.h"

namespace zeek::detail {

class ConstExpr;




class ZInst {
public:
    ZInst(ZOp _op, ZAMOpType _op_type) {
        op = _op;
        op_type = _op_type;
        ASSERT(ZAM::curr_loc);
        loc = ZAM::curr_loc;
    }


    ZInst() {
        ASSERT(ZAM::curr_loc);
        loc = ZAM::curr_loc;
    }

    virtual ~ZInst() = default;


    void Dump(FILE* f, zeek_uint_t inst_num, const FrameReMap* mappings, const std::string& prefix) const;
    void Dump(FILE* f, const std::string& prefix, const std::string& id1, const std::string& id2,
              const std::string& id3, const std::string& id4) const;






    std::string VName(int n, zeek_uint_t inst_num, const FrameReMap* mappings) const;



    int NumFrameSlots() const;


    int NumSlots() const;


    ValPtr ConstVal() const;



    bool IsLoopIterationAdvancement() const;



    bool AssignsToSlot1() const;



    bool AssignsToSlot(int slot) const;






    void TrackRecordTypeForField(const RecordTypePtr& rt, int f);
    void TrackRecordTypesForFields(const RecordTypePtr& rt1, int f1, const RecordTypePtr& rt2, int f2);

    std::shared_ptr<ZAMLocInfo> ZAMLoc() const { return loc; }


    std::string ConstDump() const;

    TraversalCode Traverse(TraversalCallback* cb) const;

    ZOp op = OP_NOP;
    ZAMOpType op_type = OP_X;







    int v1 = -1, v2 = -1, v3 = -1, v4 = -1;

    ZVal c;



protected:





    TypePtr t;

    TypePtr t2;

public:
    const TypePtr& GetType() const { return t; }
    const TypePtr& GetType2() const { return t2; }





    ZInstAux* aux = nullptr;



    std::shared_ptr<ZAMLocInfo> loc;



    std::optional<bool> is_managed;
};





class ZInstI : public ZInst {
public:


    ZInstI(ZOp _op) : ZInst(_op, OP_X) {
        op = _op;
        op_type = OP_X;
    }

    ZInstI(ZOp _op, int _v1) : ZInst(_op, OP_V) { v1 = _v1; }

    ZInstI(ZOp _op, int _v1, int _v2) : ZInst(_op, OP_VV) {
        v1 = _v1;
        v2 = _v2;
    }

    ZInstI(ZOp _op, int _v1, int _v2, int _v3) : ZInst(_op, OP_VVV) {
        v1 = _v1;
        v2 = _v2;
        v3 = _v3;
    }

    ZInstI(ZOp _op, int _v1, int _v2, int _v3, int _v4) : ZInst(_op, OP_VVVV) {
        v1 = _v1;
        v2 = _v2;
        v3 = _v3;
        v4 = _v4;
    }

    ZInstI(ZOp _op, const ConstExpr* ce) : ZInst(_op, OP_C) { InitConst(ce); }

    ZInstI(ZOp _op, int _v1, const ConstExpr* ce) : ZInst(_op, OP_VC) {
        v1 = _v1;
        InitConst(ce);
    }

    ZInstI(ZOp _op, int _v1, int _v2, const ConstExpr* ce) : ZInst(_op, OP_VVC) {
        v1 = _v1;
        v2 = _v2;
        InitConst(ce);
    }

    ZInstI(ZOp _op, int _v1, int _v2, int _v3, const ConstExpr* ce) : ZInst(_op, OP_VVVC) {
        v1 = _v1;
        v2 = _v2;
        v3 = _v3;
        InitConst(ce);
    }


    ZInstI() = default;


    void Dump(FILE* f, const FrameMap* frame_ids, const FrameReMap* remappings) const;




    std::string VName(int n, const FrameMap* frame_ids, const FrameReMap* remappings) const;



    bool DoesNotContinue() const;




    bool IsUnconditionalBranch() const { return op == OP_GOTO_b; }


    bool IsDirectAssignment() const;


    bool HasCaptures() const;



    bool HasSideEffects() const;



    bool UsesSlot(int slot) const;



    bool UsesSlots(int& s1, int& s2, int& s3, int& s4) const;


    void UpdateSlots(std::vector<int>& slot_mapping);



    bool IsGlobalLoad() const;



    bool IsCaptureLoad() const;



    bool IsNonLocalLoad() const { return IsGlobalLoad() || IsCaptureLoad(); }



    bool IsLoad() const { return op_type == OP_VV_FRAME || IsNonLocalLoad(); }


    bool IsGlobalStore() const { return op == OP_STORE_GLOBAL_g; }

    void CheckIfManaged(const TypePtr& t) { is_managed = ZVal::IsManagedType(t); }

    void SetType(TypePtr _t) {
        t = std::move(_t);
        ASSERT(t);
        if ( t )
            CheckIfManaged(t);
    }

    void SetType2(TypePtr _t) { t2 = std::move(_t); }



    bool live = true;



    bool loop_start = false;





    int loop_depth = 0;


    ZInstI* target = nullptr;
    int target_slot = 0;



    int inst_num = -1;



    int num_labels = 0;

private:

    void InitConst(const ConstExpr* ce);
};


extern const char* ZOP_name(ZOp op);





extern ZOp AssignmentFlavor(ZOp orig, TypeTag tag, bool strict = true);




extern std::unordered_map<ZOp, std::unordered_map<TypeTag, ZOp>> assignment_flavor;




extern std::unordered_map<ZOp, ZOp> assignmentless_op;



extern std::unordered_map<ZOp, ZAMOpType> assignmentless_op_class;

}
