

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "zeek/EventHandler.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/StmtBase.h"
#include "zeek/Timer.h"
#include "zeek/TraverseTypes.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/ZeekArgs.h"
#include "zeek/ZeekList.h"

namespace zeek {
template<class T>
class IntrusivePtr;

namespace detail {

class Frame;
class Scope;
class FunctionIngredients;
class WhenInfo;
using IDPtr = IntrusivePtr<ID>;
using ScopePtr = IntrusivePtr<Scope>;
using ScriptFuncPtr = IntrusivePtr<ScriptFunc>;
using FunctionIngredientsPtr = std::shared_ptr<FunctionIngredients>;

enum ExprTag : int8_t {
    EXPR_ANY = -1,
    EXPR_NAME,
    EXPR_CONST,
    EXPR_CLONE,
    EXPR_INCR,
    EXPR_DECR,
    EXPR_NOT,
    EXPR_COMPLEMENT,
    EXPR_POSITIVE,
    EXPR_NEGATE,
    EXPR_ADD,
    EXPR_SUB,
    EXPR_AGGR_ADD,
    EXPR_AGGR_DEL,
    EXPR_ADD_TO,
    EXPR_REMOVE_FROM,
    EXPR_TIMES,
    EXPR_DIVIDE,
    EXPR_MASK,
    EXPR_MOD,
    EXPR_AND,
    EXPR_OR,
    EXPR_XOR,
    EXPR_LSHIFT,
    EXPR_RSHIFT,
    EXPR_AND_AND,
    EXPR_OR_OR,
    EXPR_LT,
    EXPR_LE,
    EXPR_EQ,
    EXPR_NE,
    EXPR_GE,
    EXPR_GT,
    EXPR_COND,
    EXPR_REF,
    EXPR_ASSIGN,
    EXPR_INDEX,
    EXPR_FIELD,
    EXPR_HAS_FIELD,
    EXPR_RECORD_CONSTRUCTOR,
    EXPR_TABLE_CONSTRUCTOR,
    EXPR_SET_CONSTRUCTOR,
    EXPR_VECTOR_CONSTRUCTOR,
    EXPR_FIELD_ASSIGN,
    EXPR_IN,
    EXPR_LIST,
    EXPR_CALL,
    EXPR_LAMBDA,
    EXPR_EVENT,
    EXPR_SCHEDULE,
    EXPR_ARITH_COERCE,
    EXPR_RECORD_COERCE,
    EXPR_TABLE_COERCE,
    EXPR_VECTOR_COERCE,
    EXPR_TO_ANY_COERCE,
    EXPR_FROM_ANY_COERCE,
    EXPR_SIZE,
    EXPR_CAST,
    EXPR_CAN_CONVERT,
    EXPR_IS,
    EXPR_INDEX_SLICE_ASSIGN,





    EXPR_INLINE,
    EXPR_APPEND_TO,
    EXPR_INDEX_ASSIGN,
    EXPR_FIELD_LHS_ASSIGN,
    EXPR_REC_ASSIGN_FIELDS,
    EXPR_REC_ADD_FIELDS,
    EXPR_REC_CONSTRUCT_WITH_REC,
    EXPR_FROM_ANY_VEC_COERCE,
    EXPR_ANY_INDEX,
    EXPR_SCRIPT_OPT_BUILTIN,

    EXPR_NOP,

#define NUM_EXPRS (int(EXPR_NOP) + 1)
};

extern const char* expr_name(ExprTag t);

class AddToExpr;
class AssignExpr;
class CallExpr;
class CanConvertExpr;
class ConstExpr;
class EventExpr;
class FieldAssignExpr;
class FieldExpr;
class ForExpr;
class HasFieldExpr;
class IndexExpr;
class IsExpr;
class LambdaExpr;
class ListExpr;
class NameExpr;
class RefExpr;

class Expr;
using CallExprPtr = IntrusivePtr<CallExpr>;
using ConstExprPtr = IntrusivePtr<ConstExpr>;
using EventExprPtr = IntrusivePtr<EventExpr>;
using ExprPtr = IntrusivePtr<Expr>;
using NameExprPtr = IntrusivePtr<NameExpr>;
using RefExprPtr = IntrusivePtr<RefExpr>;
using LambdaExprPtr = IntrusivePtr<LambdaExpr>;

class Stmt;
using StmtPtr = IntrusivePtr<Stmt>;

class ExprOptInfo;

class Expr : public Obj {
public:
    const TypePtr& GetType() const { return type; }

    template<class T>
    IntrusivePtr<T> GetType() const {
        return cast_intrusive<T>(type);
    }

    ExprTag Tag() const { return tag; }

    Expr* Ref() {
        zeek::Ref(this);
        return this;
    }
    ExprPtr ThisPtr() { return {NewRef{}, this}; }



    virtual ValPtr Eval(Frame* f) const = 0;


    virtual void Assign(Frame* f, ValPtr v);



    virtual TypePtr InitType() const;





    virtual bool IsRecordElement(TypeDecl* td) const;


    virtual bool IsPure() const { return true; }


    bool IsConst() const { return tag == EXPR_CONST; }


    bool IsError() const;


    void SetError();
    void SetError(const char* msg);



    inline Val* ExprVal() const;


    bool IsZero() const;


    bool IsOne() const;



    virtual bool CanAdd() const;
    virtual bool CanDel() const;


    virtual TypePtr AddType() const;
    virtual TypePtr DelType() const;

    virtual ValPtr Add(Frame* f);
    virtual ValPtr Delete(Frame* f);




    virtual ExprPtr MakeLvalue();




    virtual bool InvertSense();



    void MarkParen() { paren = true; }
    bool IsParen() const { return paren; }



#define ZEEK_EXPR_ACCESSOR_DECLS(ctype)                                                                                \
    const ctype* As##ctype() const;                                                                                    \
    ctype* As##ctype();                                                                                                \
    IntrusivePtr<ctype> As##ctype##Ptr();


    ZEEK_EXPR_ACCESSOR_DECLS(AddToExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(AssignExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(CallExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(CanConvertExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(ConstExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(EventExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(FieldAssignExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(FieldExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(ForExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(HasFieldExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(IndexExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(IsExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(LambdaExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(ListExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(NameExpr)
    ZEEK_EXPR_ACCESSOR_DECLS(RefExpr)

    void Describe(ODesc* d) const final;

    virtual TraversalCode Traverse(TraversalCallback* cb) const = 0;


    virtual ExprPtr Duplicate() = 0;


    virtual ExprPtr Inline(Inliner* inl) { return ThisPtr(); }



    bool IsSingleton(Reducer* r) const { return (tag == EXPR_NAME && IsReduced(r)) || tag == EXPR_CONST; }


    virtual bool HasNoSideEffects() const { return IsPure(); }



    virtual bool IsReduced(Reducer* c) const;


    virtual bool HasReducedOps(Reducer* c) const;



    virtual bool HasConstantOps() const {
        return GetOp1() && GetOp1()->IsConst() &&
               (! GetOp2() || (GetOp2()->IsConst() && (! GetOp3() || GetOp3()->IsConst())));
    }



    bool IsReducedConditional(Reducer* c) const;



    bool IsReducedFieldAssignment(Reducer* c) const;


    bool IsFieldAssignable(const Expr* e) const;






    virtual bool WillTransform(Reducer* c) const { return false; }


    virtual bool WillTransformInConditional(Reducer* c) const { return false; }






    virtual bool IsSafeSubstitution(const ExprPtr& e, const ValPtr& v) const { return true; }


    ExprPtr TransformMe(ExprPtr new_me, Reducer* c, StmtPtr& red_stmt);








    virtual ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt);
    virtual ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) { return Reduce(c, red_stmt); }



    virtual StmtPtr ReduceToSingletons(Reducer* c);


    ExprPtr ReduceToConditional(Reducer* c, StmtPtr& red_stmt);




    virtual ExprPtr TransformToConditional(Reducer* c, StmtPtr& red_stmt);



    ExprPtr ReduceToFieldAssignment(Reducer* c, StmtPtr& red_stmt);



    void AssignToIndex(ValPtr v1, ValPtr v2, ValPtr v3) const;



    ExprPtr AssignToTemporary(ExprPtr e, Reducer* c, StmtPtr& red_stmt);

    ExprPtr AssignToTemporary(Reducer* c, StmtPtr& red_stmt) { return AssignToTemporary(ThisPtr(), c, red_stmt); }



    virtual ValPtr FoldVal() const { return nullptr; }


    ValPtr MakeZero(TypeTag t) const;
    ConstExprPtr MakeZeroExpr(TypeTag t) const;



    virtual ExprPtr GetOp1() const;
    virtual ExprPtr GetOp2() const;
    virtual ExprPtr GetOp3() const;


    virtual void SetOp1(ExprPtr new_op);
    virtual void SetOp2(ExprPtr new_op);
    virtual void SetOp3(ExprPtr new_op);


    StmtPtr MergeStmts(StmtPtr s1, StmtPtr s2, StmtPtr s3 = nullptr) const;








    virtual ExprPtr SetSucc(Expr* succ) {
        succ->SetLocationInfo(GetLocationInfo());
        if ( IsParen() )
            succ->MarkParen();
        return {AdoptRef{}, succ};
    }



    ExprOptInfo* GetOptInfo() const { return opt_info; }


    static int GetNumExprs() { return num_exprs; }


    static void ResetNumExprs() { num_exprs = 0; }

    ~Expr() override;

protected:
    Expr() = default;
    explicit Expr(ExprTag arg_tag);

    virtual void ExprDescribe(ODesc* d) const = 0;
    void AddTag(ODesc* d) const;


    virtual void Canonicalize();

    void SetType(TypePtr t);



    void ExprError(const char msg[]);



    [[noreturn]] void RuntimeError(const std::string& msg) const;
    [[noreturn]] void RuntimeErrorWithCallStack(const std::string& msg) const;

    ExprTag tag;
    bool paren;
    TypePtr type;



    ExprOptInfo* opt_info;


    static int num_exprs;
};

class NameExpr final : public Expr {
public:
    explicit NameExpr(IDPtr id, bool const_init = false);

    bool CanDel() const override;
    ValPtr Delete(Frame* f) override;

    ID* Id() const { return id.get(); }
    const IDPtr& IdPtr() const;

    ValPtr Eval(Frame* f) const override;
    void Assign(Frame* f, ValPtr v) override;
    ExprPtr MakeLvalue() override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    ExprPtr Duplicate() override;
    bool HasNoSideEffects() const override { return true; }
    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override { return IsReduced(c); }
    bool WillTransform(Reducer* c) const override { return ! IsReduced(c); }
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    ValPtr FoldVal() const override;

protected:
    void ExprDescribe(ODesc* d) const override;



    bool FoldableGlobal() const;

    IDPtr id;
    bool in_const_init;
};

class ConstExpr final : public Expr {
public:
    explicit ConstExpr(ValPtr val);

    Val* Value() const { return val.get(); }
    ValPtr ValuePtr() const { return val; }

    ValPtr Eval(Frame* f) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    ExprPtr Duplicate() override;

    ValPtr FoldVal() const override {
        if ( type->Tag() == TYPE_OPAQUE )



            return nullptr;

        return val;
    }

protected:
    void ExprDescribe(ODesc* d) const override;
    ValPtr val;
};

class UnaryExpr : public Expr {
public:
    Expr* Op() const { return op.get(); }




    ValPtr Eval(Frame* f) const override;

    bool IsPure() const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    ExprPtr Inline(Inliner* inl) override;

    bool HasNoSideEffects() const override;
    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

    ExprPtr GetOp1() const final { return op; }
    void SetOp1(ExprPtr _op) final { op = std::move(_op); }

protected:
    UnaryExpr(ExprTag arg_tag, ExprPtr arg_op);

    void ExprDescribe(ODesc* d) const override;


    virtual ValPtr Fold(Val* v) const;

    ExprPtr op;
};

class BinaryExpr : public Expr {
public:
    Expr* Op1() const { return op1.get(); }
    Expr* Op2() const { return op2.get(); }

    bool IsPure() const override;




    ValPtr Eval(Frame* f) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    ExprPtr Inline(Inliner* inl) override;

    bool HasNoSideEffects() const override;
    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

    bool IsSafeSubstitution(const ExprPtr& e, const ValPtr& v) const override;


    virtual bool IsSafeSubstitution(const ValPtr& v1, const ValPtr& v2) const { return true; }

    ExprPtr GetOp1() const final { return op1; }
    ExprPtr GetOp2() const final { return op2; }

    void SetOp1(ExprPtr _op) final { op1 = std::move(_op); }
    void SetOp2(ExprPtr _op) final { op2 = std::move(_op); }

protected:
    BinaryExpr(ExprTag arg_tag, ExprPtr arg_op1, ExprPtr arg_op2)
        : Expr(arg_tag), op1(std::move(arg_op1)), op2(std::move(arg_op2)) {
        if ( ! (op1 && op2) )
            return;
        if ( op1->IsError() || op2->IsError() )
            SetError();
    }


    virtual ValPtr Fold(Val* v1, Val* v2) const;


    virtual ValPtr StringFold(Val* v1, Val* v2) const;


    virtual ValPtr PatternFold(Val* v1, Val* v2) const;


    virtual ValPtr SetFold(Val* v1, Val* v2) const;


    virtual ValPtr TableFold(Val* v1, Val* v2) const;


    virtual ValPtr AddrFold(Val* v1, Val* v2) const;
    virtual ValPtr SubNetFold(Val* v1, Val* v2) const;

    bool BothConst() const { return op1->IsConst() && op2->IsConst(); }


    void SwapOps();


    void PromoteOps(TypeTag t);



    void PromoteType(TypeTag t, bool is_vector);




    void PromoteForInterval(ExprPtr& op);

    void ExprDescribe(ODesc* d) const override;





    bool CheckForRHSList();

    ExprPtr op1;
    ExprPtr op2;
};

class CloneExpr final : public UnaryExpr {
public:
    explicit CloneExpr(ExprPtr op);
    ValPtr Eval(Frame* f) const override;


    ExprPtr Duplicate() override;

protected:
    ValPtr Fold(Val* v) const override;
};

class IncrExpr final : public UnaryExpr {
public:
    IncrExpr(ExprTag tag, ExprPtr op);

    ValPtr Eval(Frame* f) const override;
    ValPtr DoSingleEval(Frame* f, Val* v) const;
    bool IsPure() const override { return false; }


    ExprPtr Duplicate() override;
    bool HasNoSideEffects() const override;
    bool WillTransform(Reducer* c) const override { return true; }
    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override { return false; }
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;
};

class ComplementExpr final : public UnaryExpr {
public:
    explicit ComplementExpr(ExprPtr op);


    ExprPtr Duplicate() override;
    bool WillTransform(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
    ValPtr Fold(Val* v) const override;
};

class NotExpr final : public UnaryExpr {
public:
    explicit NotExpr(ExprPtr op);


    ExprPtr Duplicate() override;
    bool WillTransform(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
    ValPtr Fold(Val* v) const override;
};

class PosExpr final : public UnaryExpr {
public:
    explicit PosExpr(ExprPtr op);


    ExprPtr Duplicate() override;
    bool WillTransform(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
    ValPtr Fold(Val* v) const override;
};

class NegExpr final : public UnaryExpr {
public:
    explicit NegExpr(ExprPtr op);


    ExprPtr Duplicate() override;
    bool WillTransform(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
    ValPtr Fold(Val* v) const override;
};

class SizeExpr final : public UnaryExpr {
public:
    explicit SizeExpr(ExprPtr op);
    ValPtr Eval(Frame* f) const override;


    ExprPtr Duplicate() override;

protected:
    ValPtr Fold(Val* v) const override;
};

class AddExpr final : public BinaryExpr {
public:
    AddExpr(ExprPtr op1, ExprPtr op2);
    void Canonicalize() override;


    ExprPtr Duplicate() override;
    bool WillTransform(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
    ExprPtr BuildSub(const ExprPtr& op1, const ExprPtr& op2);
};


class AggrAddDelExpr : public UnaryExpr {
public:
    explicit AggrAddDelExpr(ExprTag _tag, ExprPtr _e) : UnaryExpr(_tag, std::move(_e)) {}

    bool IsPure() const override { return false; }


    bool IsReduced(Reducer* c) const override { return HasReducedOps(c); }
    bool HasReducedOps(Reducer* c) const override { return op->HasReducedOps(c); }
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
};

class AggrAddExpr final : public AggrAddDelExpr {
public:
    explicit AggrAddExpr(ExprPtr e);


    ExprPtr Duplicate() override;

protected:
    ValPtr Eval(Frame* f) const override;
};

class AggrDelExpr final : public AggrAddDelExpr {
public:
    explicit AggrDelExpr(ExprPtr e);


    ExprPtr Duplicate() override;

protected:
    ValPtr Eval(Frame* f) const override;
};

class AddToExpr final : public BinaryExpr {
public:
    AddToExpr(ExprPtr op1, ExprPtr op2);
    ValPtr Eval(Frame* f) const override;

    bool IsVectorElemAppend() const { return is_vector_elem_append; }


    bool IsPure() const override { return false; }
    ExprPtr Duplicate() override;
    bool HasReducedOps(Reducer* c) const override { return false; }
    bool WillTransform(Reducer* c) const override { return true; }
    bool IsReduced(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;

private:

    bool is_vector_elem_append = false;
};

class RemoveFromExpr final : public BinaryExpr {
public:
    bool IsPure() const override { return false; }
    RemoveFromExpr(ExprPtr op1, ExprPtr op2);
    ValPtr Eval(Frame* f) const override;


    ExprPtr Duplicate() override;
    bool HasReducedOps(Reducer* c) const override { return false; }
    bool WillTransform(Reducer* c) const override { return true; }
    bool IsReduced(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;
};

class SubExpr final : public BinaryExpr {
public:
    SubExpr(ExprPtr op1, ExprPtr op2);


    ExprPtr Duplicate() override;
    bool WillTransform(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
};

class TimesExpr final : public BinaryExpr {
public:
    TimesExpr(ExprPtr op1, ExprPtr op2);
    void Canonicalize() override;


    ExprPtr Duplicate() override;
    bool WillTransform(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
};

class DivideExpr final : public BinaryExpr {
public:
    DivideExpr(ExprPtr op1, ExprPtr op2);


    ExprPtr Duplicate() override;
    bool WillTransform(Reducer* c) const override;
    bool IsSafeSubstitution(const ValPtr& v1, const ValPtr& v2) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
};

class MaskExpr final : public BinaryExpr {
public:
    MaskExpr(ExprPtr op1, ExprPtr op2);


    ExprPtr Duplicate() override;
    bool IsSafeSubstitution(const ValPtr& v1, const ValPtr& v2) const override;

protected:
    ValPtr AddrFold(Val* v1, Val* v2) const override;
    uint32_t GetMask(const Val* v) const;
};

class ModExpr final : public BinaryExpr {
public:
    ModExpr(ExprPtr op1, ExprPtr op2);


    ExprPtr Duplicate() override;
    bool IsSafeSubstitution(const ValPtr& v1, const ValPtr& v2) const override;
};

class BoolExpr final : public BinaryExpr {
public:
    BoolExpr(ExprTag tag, ExprPtr op1, ExprPtr op2);

    ValPtr Eval(Frame* f) const override;
    ValPtr DoSingleEval(Frame* f, ValPtr v1, Expr* op2) const;


    ExprPtr Duplicate() override;
    bool WillTransform(Reducer* c) const override;
    bool WillTransformInConditional(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    ExprPtr TransformToConditional(Reducer* c, StmtPtr& red_stmt) override;

protected:
    bool IsTrue(const ExprPtr& e) const;
    bool IsFalse(const ExprPtr& e) const;
};

class BitExpr final : public BinaryExpr {
public:
    BitExpr(ExprTag tag, ExprPtr op1, ExprPtr op2);


    ExprPtr Duplicate() override;
    bool WillTransform(Reducer* c) const override;
    bool IsSafeSubstitution(const ValPtr& v1, const ValPtr& v2) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
};


class CmpExpr : public BinaryExpr {
protected:
    CmpExpr(ExprTag tag, ExprPtr op1, ExprPtr op2);

    void Canonicalize() override;

    bool WillTransform(Reducer* c) const override;
    bool WillTransformInConditional(Reducer* c) const override;
    bool IsReduced(Reducer* c) const override;
    ExprPtr TransformToConditional(Reducer* c, StmtPtr& red_stmt) override;

    bool IsHasElementsTest() const;
    ExprPtr BuildHasElementsTest() const;
};

class EqExpr final : public CmpExpr {
public:
    EqExpr(ExprTag tag, ExprPtr op1, ExprPtr op2);


    ExprPtr Duplicate() override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    bool InvertSense() override;

protected:
    ValPtr Fold(Val* v1, Val* v2) const override;
};

class RelExpr final : public CmpExpr {
public:
    RelExpr(ExprTag tag, ExprPtr op1, ExprPtr op2);


    ExprPtr Duplicate() override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    bool InvertSense() override;
};

class CondExpr final : public Expr {
public:
    CondExpr(ExprPtr op1, ExprPtr op2, ExprPtr op3);

    const Expr* Op1() const { return op1.get(); }
    const Expr* Op2() const { return op2.get(); }
    const Expr* Op3() const { return op3.get(); }

    ValPtr Eval(Frame* f) const override;
    bool IsPure() const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    ExprPtr Duplicate() override;
    ExprPtr Inline(Inliner* inl) override;

    bool WillTransform(Reducer* c) const override;
    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    StmtPtr ReduceToSingletons(Reducer* c) override;

    ExprPtr GetOp1() const final { return op1; }
    ExprPtr GetOp2() const final { return op2; }
    ExprPtr GetOp3() const final { return op3; }

    void SetOp1(ExprPtr _op) final { op1 = std::move(_op); }
    void SetOp2(ExprPtr _op) final { op2 = std::move(_op); }
    void SetOp3(ExprPtr _op) final { op3 = std::move(_op); }

protected:
    void ExprDescribe(ODesc* d) const override;

    bool IsMinOrMax(Reducer* c) const;
    ExprPtr TransformToMinOrMax() const;

    ExprPtr op1;
    ExprPtr op2;
    ExprPtr op3;
};

class RefExpr final : public UnaryExpr {
public:
    explicit RefExpr(ExprPtr op);

    void Assign(Frame* f, ValPtr v) override;
    ExprPtr MakeLvalue() override;


    ExprPtr Duplicate() override;

    bool WillTransform(Reducer* c) const override;
    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;


    StmtPtr ReduceToLHS(Reducer* c);
};

class AssignExpr : public BinaryExpr {
public:


    AssignExpr(ExprPtr op1, ExprPtr op2, bool is_init, ValPtr val = nullptr, const AttributesPtr& attrs = nullptr,
               bool type_check = true);

    ValPtr Eval(Frame* f) const override;
    TypePtr InitType() const override;
    bool IsRecordElement(TypeDecl* td) const override;
    bool IsPure() const override { return false; }


    ExprPtr Duplicate() override;

    bool HasNoSideEffects() const override;
    bool WillTransform(Reducer* c) const override { return true; }
    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    ExprPtr ReduceToSingleton(Reducer* c, StmtPtr& red_stmt) override;


    bool IsTemp() const { return is_temp; }
    void SetIsTemp() { is_temp = true; }







    ValPtr AssignVal() { return val; }
    const ValPtr& AssignVal() const { return val; }

protected:
    bool TypeCheck(const AttributesPtr& attrs = nullptr);
    bool TypeCheckArithmetics(TypeTag bt1, TypeTag bt2);

    bool is_init;
    bool is_temp = false;

    ValPtr val;
};

class IndexSliceAssignExpr final : public AssignExpr {
public:
    IndexSliceAssignExpr(ExprPtr op1, ExprPtr op2, bool is_init);
    ValPtr Eval(Frame* f) const override;


    ExprPtr Duplicate() override;
};

class IndexExpr : public BinaryExpr {
public:
    IndexExpr(ExprPtr op1, ListExprPtr op2, bool is_slice = false, bool is_inside_when = false);

    bool CanAdd() const override;
    bool CanDel() const override;

    ValPtr Add(Frame* f) override;
    ValPtr Delete(Frame* f) override;

    void Assign(Frame* f, ValPtr v) override;
    ExprPtr MakeLvalue() override;



    ValPtr Eval(Frame* f) const override;

    bool IsSlice() const { return is_slice; }
    bool IsInsideWhen() const { return is_inside_when; }


    ExprPtr Duplicate() override;

    bool HasReducedOps(Reducer* c) const override;
    StmtPtr ReduceToSingletons(Reducer* c) override;

protected:
    ValPtr Fold(Val* v1, Val* v2) const override;

    void ExprDescribe(ODesc* d) const override;

    bool is_slice;
    bool is_inside_when;
    bool is_pattern_table = false;
};







extern VectorValPtr index_slice(VectorVal* vect, const ListVal* lv);



extern VectorValPtr index_slice(VectorVal* vect, int first, int last);



extern StringValPtr index_string(const String* s, const ListVal* lv);


extern VectorValPtr vector_bool_select(VectorTypePtr vt, const VectorVal* v1, const VectorVal* v2);



extern VectorValPtr vector_int_select(VectorTypePtr vt, const VectorVal* v1, const VectorVal* v2);








class IndexExprWhen final : public IndexExpr {
public:
    static inline std::vector<ValPtr> results = {};
    static inline int evaluating = 0;

    static void StartEval() { ++evaluating; }

    static void EndEval() { --evaluating; }

    static std::vector<ValPtr> TakeAllResults() {
        auto rval = std::move(results);
        results = {};
        return rval;
    }

    IndexExprWhen(ExprPtr op1, ListExprPtr op2, bool is_slice = false)
        : IndexExpr(std::move(op1), std::move(op2), is_slice, true) {}

    ValPtr Eval(Frame* f) const override {
        auto v = IndexExpr::Eval(f);

        if ( v && evaluating > 0 )
            results.emplace_back(v);

        return v;
    }


    ExprPtr Duplicate() override;
};

class FieldExpr final : public UnaryExpr {
public:
    FieldExpr(ExprPtr op, const char* field_name);
    ~FieldExpr() override;

    int Field() const { return field; }
    const char* FieldName() const { return field_name; }

    bool CanDel() const override;

    void Assign(Frame* f, ValPtr v) override;
    ValPtr Delete(Frame* f) override;

    ExprPtr MakeLvalue() override;


    ExprPtr Duplicate() override;

protected:
    void Assign(ValPtr lhs, ValPtr rhs);
    ValPtr Fold(Val* v) const override;

    void ExprDescribe(ODesc* d) const override;

    const char* field_name;
    const TypeDecl* td = nullptr;
    int field = -1;
};



class HasFieldExpr final : public UnaryExpr {
public:
    HasFieldExpr(ExprPtr op, const char* field_name);
    ~HasFieldExpr() override;

    const char* FieldName() const { return field_name; }
    int Field() const { return field; }


    ExprPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
    ValPtr Fold(Val* v) const override;

    void ExprDescribe(ODesc* d) const override;

    const char* field_name = nullptr;
    int field = -1;
};

class RecordConstructorExpr final : public Expr {
public:
    explicit RecordConstructorExpr(ListExprPtr constructor_list);




    explicit RecordConstructorExpr(RecordTypePtr known_rt, ListExprPtr constructor_list,
                                   bool check_mandatory_fields = true);

    ListExprPtr Op() const { return op; }
    const auto& Map() const { return map; }

    ValPtr Eval(Frame* f) const override;

    bool IsPure() const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    ExprPtr Duplicate() override;
    ExprPtr Inline(Inliner* inl) override;

    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    StmtPtr ReduceToSingletons(Reducer* c) override;

protected:
    void ExprDescribe(ODesc* d) const override;

    ListExprPtr op;
    std::optional<std::vector<int>> map;
};

class TableConstructorExpr final : public UnaryExpr {
public:
    TableConstructorExpr(ListExprPtr constructor_list, std::unique_ptr<std::vector<AttrPtr>> attrs,
                         TypePtr arg_type = nullptr, AttributesPtr arg_attrs = nullptr);

    void SetAttrs(AttributesPtr _attrs) { attrs = std::move(_attrs); }
    const AttributesPtr& GetAttrs() const { return attrs; }

    ValPtr Eval(Frame* f) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    ExprPtr Duplicate() override;

    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    StmtPtr ReduceToSingletons(Reducer* c) override;

protected:
    void ExprDescribe(ODesc* d) const override;

    AttributesPtr attrs;
};

class SetConstructorExpr final : public UnaryExpr {
public:
    SetConstructorExpr(ListExprPtr constructor_list, std::unique_ptr<std::vector<AttrPtr>> attrs,
                       TypePtr arg_type = nullptr, AttributesPtr arg_attrs = nullptr);

    void SetAttrs(AttributesPtr _attrs) { attrs = std::move(_attrs); }
    const AttributesPtr& GetAttrs() const { return attrs; }

    ValPtr Eval(Frame* f) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    ExprPtr Duplicate() override;

    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    StmtPtr ReduceToSingletons(Reducer* c) override;

protected:
    void ExprDescribe(ODesc* d) const override;

    AttributesPtr attrs;
};

class VectorConstructorExpr final : public UnaryExpr {
public:
    explicit VectorConstructorExpr(ListExprPtr constructor_list, TypePtr arg_type = nullptr);

    ValPtr Eval(Frame* f) const override;


    ExprPtr Duplicate() override;

    bool HasReducedOps(Reducer* c) const override;

protected:
    void ExprDescribe(ODesc* d) const override;
};

class FieldAssignExpr final : public UnaryExpr {
public:
    FieldAssignExpr(const char* field_name, ExprPtr value);

    const char* FieldName() const { return field_name.c_str(); }







    bool PromoteTo(TypePtr t);

    bool IsRecordElement(TypeDecl* td) const override;


    ExprPtr Duplicate() override;
    bool WillTransform(Reducer* c) const override { return true; }
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
    void ExprDescribe(ODesc* d) const override;

    std::string field_name;
};

class ArithCoerceExpr final : public UnaryExpr {
public:
    ArithCoerceExpr(ExprPtr op, TypeTag t);


    ExprPtr Duplicate() override;

    bool WillTransform(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    bool IsSafeSubstitution(const ExprPtr& e, const ValPtr& v) const override;

protected:
    ValPtr FoldSingleVal(ValPtr v, const TypePtr& t) const;
    ValPtr Fold(Val* v) const override;
};

class RecordCoerceExpr final : public UnaryExpr {
public:
    RecordCoerceExpr(ExprPtr op, RecordTypePtr r);


    ExprPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    bool WillTransform(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

    const std::vector<int>& Map() const { return map; }

protected:
    ValPtr Fold(Val* v) const override;



    std::vector<int> map;
};

extern RecordValPtr coerce_to_record(RecordTypePtr rt, Val* v, const std::vector<int>& map);

class TableCoerceExpr final : public UnaryExpr {
public:
    TableCoerceExpr(ExprPtr op, TableTypePtr r, bool type_check = true);


    ExprPtr Duplicate() override;

protected:
    ValPtr Fold(Val* v) const override;
};

class VectorCoerceExpr final : public UnaryExpr {
public:
    VectorCoerceExpr(ExprPtr op, VectorTypePtr v);


    ExprPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    bool WillTransform(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
    ValPtr Fold(Val* v) const override;
};

class ScheduleTimer final : public Timer {
public:
    ScheduleTimer(const EventHandlerPtr& event, zeek::Args args, double t);

    void Dispatch(double t, bool is_expire) override;

protected:
    EventHandlerPtr event;
    zeek::Args args;
};

class ScheduleExpr final : public Expr {
public:
    ScheduleExpr(ExprPtr when, EventExprPtr event);

    bool IsPure() const override { return false; }

    ValPtr Eval(Frame* f) const override;

    Expr* When() const { return when.get(); }
    EventExpr* Event() const { return event.get(); }

    TraversalCode Traverse(TraversalCallback* cb) const override;


    ExprPtr Duplicate() override;
    ExprPtr Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

    ExprPtr GetOp1() const final;
    ExprPtr GetOp2() const final;

    void SetOp1(ExprPtr _op) final;
    void SetOp2(ExprPtr _op) final;

protected:
    void ExprDescribe(ODesc* d) const override;

    ExprPtr when;
    EventExprPtr event;
};

class InExpr final : public BinaryExpr {
public:
    InExpr(ExprPtr op1, ExprPtr op2);


    ExprPtr Duplicate() override;

    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
    ValPtr Fold(Val* v1, Val* v2) const override;
};

class CallExpr final : public Expr {
public:
    CallExpr(ExprPtr func, ListExprPtr args, bool in_hook = false, bool in_when = false);

    Expr* Func() const { return func.get(); }
    ExprPtr FuncPtr() const { return func; }
    ListExpr* Args() const { return args.get(); }
    ListExprPtr ArgsPtr() const { return args; }

    bool IsPure() const override;
    bool IsInWhen() const { return in_when; }

    ValPtr Eval(Frame* f) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    ExprPtr Duplicate() override;
    ExprPtr Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    bool WillTransform(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    StmtPtr ReduceToSingletons(Reducer* c) override;

protected:
    void ExprDescribe(ODesc* d) const override;

    bool IsFoldableBiF() const;
    bool AllConstArgs() const;
    bool CheckForBuiltin() const;
    bool IsEmptyHook() const;
    ExprPtr TransformToBuiltin();

    ExprPtr func;
    ListExprPtr args;
    bool in_when;
};






class LambdaExpr final : public Expr {
public:
    LambdaExpr(FunctionIngredientsPtr ingredients, IDPList outer_ids, std::string name = "",
               StmtPtr when_parent = nullptr);

    const std::string& Name() const { return my_name; }

    const IDPList& OuterIDs() const { return outer_ids; }



    using CaptureList = std::vector<FuncType::Capture>;
    const std::optional<CaptureList>& GetCaptures() const { return captures; }

    ValPtr Eval(Frame* f) const override;
    TraversalCode Traverse(TraversalCallback* cb) const override;

    ScopePtr GetScope() const;


    ExprPtr Duplicate() override;

    const ScriptFuncPtr& PrimaryFunc() const { return primary_func; }

    const FunctionIngredientsPtr& Ingredients() const { return ingredients; }

    void ReplaceBody(StmtPtr new_body);

    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    StmtPtr ReduceToSingletons(Reducer* c) override;

protected:

    LambdaExpr(LambdaExpr* orig);

    void ExprDescribe(ODesc* d) const override;

private:
    friend class WhenInfo;






    void SetPrivateCaptures(const IDSet& pcaps) { private_captures = pcaps; }

    bool CheckCaptures(StmtPtr when_parent);
    void BuildName();

    void UpdateCaptures(Reducer* c);

    FunctionIngredientsPtr ingredients;
    ScriptFuncPtr primary_func;
    IDPtr lambda_id;
    IDPList outer_ids;
    std::optional<CaptureList> captures;
    IDSet private_captures;

    std::string my_name;
};



class ListExpr : public Expr {
public:
    ListExpr();
    explicit ListExpr(ExprPtr e);
    ~ListExpr() override;

    void Append(ExprPtr e);

    const ExprPList& Exprs() const { return exprs; }
    ExprPList& Exprs() { return exprs; }


    bool IsPure() const override;


    bool HasConstantOps() const override;

    ValPtr Eval(Frame* f) const override;

    TypePtr InitType() const override;
    ExprPtr MakeLvalue() override;
    void Assign(Frame* f, ValPtr v) override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    ExprPtr Duplicate() override;
    ExprPtr Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    bool HasReducedOps(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    StmtPtr ReduceToSingletons(Reducer* c) override;

protected:
    void ExprDescribe(ODesc* d) const override;

    ExprPList exprs;
};

class EventExpr final : public Expr {
public:
    EventExpr(const char* name, ListExprPtr args);

    const char* Name() const { return name.c_str(); }
    ListExpr* Args() const { return args.get(); }
    EventHandlerPtr Handler() const { return handler; }

    ValPtr Eval(Frame* f) const override;

    TraversalCode Traverse(TraversalCallback* cb) const override;


    ExprPtr Duplicate() override;
    ExprPtr Inline(Inliner* inl) override;

    bool IsReduced(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;
    StmtPtr ReduceToSingletons(Reducer* c) override;

    ExprPtr GetOp1() const final { return args; }
    void SetOp1(ExprPtr _op) final { args = {NewRef{}, _op->AsListExpr()}; }

protected:
    void ExprDescribe(ODesc* d) const override;

    std::string name;
    EventHandlerPtr handler;
    ListExprPtr args;
};

class RecordAssignExpr final : public ListExpr {
public:
    RecordAssignExpr(const ExprPtr& record, const ExprPtr& init_list, bool is_init);
};

class CanConvertExpr final : public UnaryExpr {
public:
    CanConvertExpr(ExprPtr op, TypePtr t);

    const TypePtr& ConversionType() const { return conversion_type; }


    ExprPtr Duplicate() override;

protected:
    ValPtr Fold(Val* v) const override;
    void ExprDescribe(ODesc* d) const override;

    TypePtr conversion_type;
};

class CastExpr final : public UnaryExpr {
public:
    CastExpr(ExprPtr op, TypePtr t);


    ExprPtr Duplicate() override;
    bool IsSafeSubstitution(const ExprPtr& e, const ValPtr& v) const override;

protected:
    ValPtr Fold(Val* v) const override;
    void ExprDescribe(ODesc* d) const override;
};



extern ValPtr cast_value(ValPtr v, const TypePtr& t, std::string& error);

class IsExpr final : public UnaryExpr {
public:
    IsExpr(ExprPtr op, TypePtr t);

    const TypePtr& TestType() const { return t; }


    ExprPtr Duplicate() override;

protected:
    ValPtr Fold(Val* v) const override;
    void ExprDescribe(ODesc* d) const override;

private:
    TypePtr t;
};



class CoerceToAnyExpr : public UnaryExpr {
public:
    CoerceToAnyExpr(ExprPtr op);

    bool IsReduced(Reducer* c) const override;
    ExprPtr Reduce(Reducer* c, StmtPtr& red_stmt) override;

protected:
    ValPtr Fold(Val* v) const override;

    ExprPtr Duplicate() override;
};


class CoerceFromAnyExpr : public UnaryExpr {
public:
    CoerceFromAnyExpr(ExprPtr op, TypePtr to_type);

protected:
    ValPtr Fold(Val* v) const override;

    ExprPtr Duplicate() override;
};



extern const char* assign_to_index(ValPtr v1, ValPtr v2, ValPtr v3, bool& iterators_invalidated);

inline Val* Expr::ExprVal() const {
    if ( ! IsConst() )
        BadTag("ExprVal::Val", expr_name(tag), expr_name(EXPR_CONST));
    return (static_cast<const ConstExpr*>(this))->Value();
}


extern ExprPtr get_assign_expr(ExprPtr op1, ExprPtr op2, bool is_init);






extern ListExprPtr expand_op(ListExprPtr op, const TypePtr& t);












extern ExprPtr check_and_promote_expr(ExprPtr e, TypePtr t);

extern bool check_and_promote_exprs(ListExpr* elements, const TypeListPtr& types);
extern bool check_and_promote_args(ListExpr* args, const RecordType* types);
extern bool check_and_promote_exprs_to_type(ListExpr* elements, TypePtr type);



extern std::optional<std::vector<ValPtr>> eval_list(Frame* f, const ListExpr* l);



extern ValPtr eval_in_isolation(const Expr* e);
inline ValPtr eval_in_isolation(const ExprPtr& e) { return eval_in_isolation(e.get()); }




extern bool expr_greater(const Expr* e1, const Expr* e2);


inline bool is_vector(Expr* e) { return e->GetType()->Tag() == TYPE_VECTOR; }
inline bool is_vector(const ExprPtr& e) { return is_vector(e.get()); }


inline bool is_list(Expr* e) { return e->GetType()->Tag() == TYPE_LIST; }

inline bool is_list(const ExprPtr& e) { return is_list(e.get()); }

}
}
