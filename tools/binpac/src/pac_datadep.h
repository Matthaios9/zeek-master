

#ifndef pac_datadep_h
#define pac_datadep_h

#include <cstdint>




#include "pac_common.h"

class DataDepVisitor;

class DataDepElement {
public:
    enum DDE_Type : uint8_t {
        ATTR,
        CASEEXPR,
        EXPR,
        FIELD,
        INPUT_BUFFER,
        PARAM,
        TYPE,
    };

    DataDepElement(DDE_Type type);
    virtual ~DataDepElement() = default;


    bool Traverse(DataDepVisitor* visitor);


    virtual bool DoTraverse(DataDepVisitor* visitor) = 0;

    DDE_Type dde_type() const { return dde_type_; }
    Expr* expr();
    Type* type();

protected:
    DDE_Type dde_type_;
    bool in_traversal = false;
};

class DataDepVisitor {
public:
    virtual ~DataDepVisitor() = default;

    virtual bool PreProcess(DataDepElement* element) = 0;
    virtual bool PostProcess(DataDepElement* element) = 0;
};

class RequiresAnalyzerContext : public DataDepVisitor {
public:

    bool PreProcess(DataDepElement* element) override;
    bool PostProcess(DataDepElement* element) override;

    bool requires_analyzer_context() const { return requires_analyzer_context_; }

    static bool compute(DataDepElement* element);

protected:
    void ProcessExpr(Expr* expr);

    bool requires_analyzer_context_ = false;
};

#endif
