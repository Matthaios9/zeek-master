

#ifndef pac_param_h
#define pac_param_h

#include "pac_common.h"
#include "pac_field.h"

class Param : public Object {
public:
    Param(ID* id, Type* type);

    ID* id() const { return id_; }
    Type* type() const { return type_; }
    const string& decl_str() const;
    Field* param_field() const { return param_field_; }

private:
    ID* id_;
    Type* type_;
    string decl_str_;
    Field* param_field_;
};

class ParamField : public Field {
public:
    ParamField(const Param* param);

    void GenInitCode(Output* out, Env* env) override;
    void GenCleanUpCode(Output* out, Env* env) override;
};


string ParamDecls(ParamList* params);

#if 0

void GenParamAssignments(ParamList *params, Output *out_cc, Env *env);


void GenParamPubDecls(ParamList *params, Output *out_h, Env *env);


void GenParamPrivDecls(ParamList *params, Output *out_h, Env *env);
#endif

#endif
