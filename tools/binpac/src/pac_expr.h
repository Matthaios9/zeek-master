

#ifndef pac_expr_h
#define pac_expr_h

#include <cstdint>

#include "pac_common.h"
#include "pac_datadep.h"

class CaseExpr;

class Expr : public Object, public DataDepElement {
public:
    enum ExprType : uint8_t {

#define EXPR_DEF(type, x, y) type,
#include "pac_expr.def"
#undef EXPR_DEF
    };

    void init();

    Expr(ID* id);
    Expr(Number* num);
    Expr(Nullptr* nullp);
    Expr(ConstString* s);
    Expr(RegEx* regex);
    Expr(ExprList* args);
    Expr(Expr* index, CaseExprList* cases);

    Expr(ExprType type, Expr* op1);
    Expr(ExprType type, Expr* op1, Expr* op2);
    Expr(ExprType type, Expr* op1, Expr* op2, Expr* op3);

    ~Expr() override;

    const char* orig() const { return orig_.c_str(); }
    const ID* id() const { return id_; }
    const char* str() const { return str_.c_str(); }
    ExprType expr_type() const { return expr_type_; }

    void AddCaseExpr(CaseExpr* case_expr);





    Type* DataType(Env* env) const;
    string DataTypeStr(Env* env) const;











    const char* EvalExpr(Output* out, Env* env);




    void ForceIDEval(Output* out_cc, Env* env);



    string SetFunc(Output* out, Env* env);




    bool ConstFold(Env* env, int* pn) const;


    bool HasReference(const ID* id) const;










    int MinimalHeaderSize(Env* env);


    bool RequiresAnalyzerContext() const;

protected:
    bool DoTraverse(DataDepVisitor* visitor) override;

private:
    ExprType expr_type_;

    int num_operands_ = 0;
    Expr* operand_[3] = {nullptr};

    ID* id_ = nullptr;
    Number* num_ = nullptr;
    ConstString* cstr_ = nullptr;
    RegEx* regex_ = nullptr;
    ExprList* args_ = nullptr;
    CaseExprList* cases_ = nullptr;
    Nullptr* nullp_ = nullptr;

    string str_;
    string orig_;

    void GenStrFromFormat(Env* env);
    void GenEval(Output* out, Env* env);
    void GenCaseEval(Output* out_cc, Env* env);
};

string OrigExprList(ExprList* exprlist);
string EvalExprList(ExprList* exprlist, Output* out, Env* env);



class CaseExpr : public Object, public DataDepElement {
public:
    CaseExpr(ExprList* index, Expr* value);
    ~CaseExpr() override;

    ExprList* index() const { return index_; }
    Expr* value() const { return value_; }

    bool HasReference(const ID* id) const;
    bool RequiresAnalyzerContext() const;

protected:
    bool DoTraverse(DataDepVisitor* visitor) override;

private:
    ExprList* index_;
    Expr* value_;
};

#endif
