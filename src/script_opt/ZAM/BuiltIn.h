




#pragma once

#include "zeek/Expr.h"
#include "zeek/script_opt/ZAM/ZOp.h"

namespace zeek::detail {

class ZInstAux;



class ZAMBuiltIn {
public:



    ZAMBuiltIn(const std::string& name, bool _ret_val_matters);
    virtual ~ZAMBuiltIn() = default;

    bool ReturnValMatters() const { return ret_val_matters; }
    bool HaveBothReturnValAndNon() const { return have_both; }








    virtual bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const = 0;







    virtual bool BuildCond(ZAMCompiler* zam, const ExprPList& args, int& branch_v) const { return false; };

protected:
    bool ret_val_matters = true;



    bool have_both = false;
};




class SimpleZBI : public ZAMBuiltIn {
public:


    SimpleZBI(const std::string& name, ZOp _op, int _nargs, bool _ret_val_matters = true);



    SimpleZBI(const std::string& name, ZOp _const_op, ZOp _op, bool _ret_val_matters = true);

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;

protected:

    ZOp op;


    ZOp const_op = OP_NOP;

    int nargs;
};


class CondZBI : public SimpleZBI {
public:
    CondZBI(const std::string& name, ZOp _op, ZOp _cond_op, int _nargs);

    bool BuildCond(ZAMCompiler* zam, const ExprPList& args, int& branch_v) const override;

protected:
    ZOp cond_op;
};


class OptAssignZBI : public SimpleZBI {
public:

    OptAssignZBI(const std::string& name, ZOp _op, ZOp _op2, int _nargs);

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;

protected:
    ZOp op2;
};



class CatZBI : public ZAMBuiltIn {
public:
    CatZBI() : ZAMBuiltIn("cat", true) {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;

private:


    ZInstAux* BuildCatAux(ZAMCompiler* zam, const ExprPList& args) const;
};




class SortZBI : public OptAssignZBI {
public:
    SortZBI() : OptAssignZBI("sort", OP_SORT_VV, OP_SORT_V, 1) {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;
};











enum BiFArgsType : uint8_t {
    VV = 0x0,
    VC = 0x1,
    CV = 0x2,
    CC = 0x3,

    VVV = 0x0,
    VVC = 0x1,
    VCV = 0x2,
    VCC = 0x3,
    CVV = 0x4,
    CVC = 0x5,
    CCV = 0x6,
    CCC = 0x7,
};


struct BiFArgInfo {
    ZOp op;
    ZAMOpType op_type;
};



using BiFArgsInfo = std::map<BiFArgsType, BiFArgInfo>;


class MultiZBI : public ZAMBuiltIn {
public:





    MultiZBI(const std::string& name, bool _ret_val_matters, BiFArgsInfo _args_info, int _type_arg = -1);




    MultiZBI(const std::string& name, BiFArgsInfo _args_info, BiFArgsInfo _assign_args_info, int _type_arg = -1);

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;

private:


    BiFArgsType ComputeArgsType(const ExprPList& args) const;

    BiFArgsInfo args_info;
    BiFArgsInfo assign_args_info;
    int type_arg;
};



extern bool IsZAM_BuiltIn(ZAMCompiler* zam, const Expr* e);




extern bool IsZAM_BuiltInCond(ZAMCompiler* zam, const CallExpr* c, int& branch_v);

}
