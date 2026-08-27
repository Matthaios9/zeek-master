








#pragma once

#include <cassert>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using std::string;
using std::vector;


enum ZAM_InstClass {
    ZIC_REGULAR,
    ZIC_COND,
    ZIC_VEC,
    ZIC_FIELD,
};


enum ZAM_OperandClass {
    ZAM_OC_CONSTANT,
    ZAM_OC_EVENT_HANDLER,
    ZAM_OC_INT,
    ZAM_OC_VAR,

    ZAM_OC_ASSIGN_FIELD,
    ZAM_OC_RECORD_FIELD,




    ZAM_OC_AUX,
    ZAM_OC_LIST,



    ZAM_OC_BRANCH,
    ZAM_OC_GLOBAL,
    ZAM_OC_STEP_ITER,
    ZAM_OC_TBL_ITER,

    ZAM_OC_NONE,
};

using OCVec = vector<ZAM_OperandClass>;





enum ZAM_Type {
    ZAM_TYPE_ADDR,
    ZAM_TYPE_ANY,
    ZAM_TYPE_DOUBLE,
    ZAM_TYPE_FUNC,
    ZAM_TYPE_INT,
    ZAM_TYPE_PATTERN,
    ZAM_TYPE_RECORD,
    ZAM_TYPE_STRING,
    ZAM_TYPE_SUBNET,
    ZAM_TYPE_TABLE,
    ZAM_TYPE_UINT,
    ZAM_TYPE_VECTOR,
    ZAM_TYPE_FILE,
    ZAM_TYPE_OPAQUE,
    ZAM_TYPE_LIST,
    ZAM_TYPE_TYPE,



    ZAM_TYPE_DEFAULT,




    ZAM_TYPE_NONE,
};




using Words = vector<string>;


struct InputLoc {
    const char* file_name;
    int line_num = 0;
};




enum EmitTarget {

    None,



    MethodDecl,
    MethodDef,



    DirectDef,






    C1Def,
    C2Def,
    C3Def,
    VDef,




    C1FieldDef,
    C2FieldDef,
    VFieldDef,



    Cond,


    OpDesc,


    MacroDesc,



    Eval,


    EvalMacros,



    Vec1Eval,
    Vec2Eval,






    AssignFlavor,







    Op1Flavor,





    OpSideEffects,



    OpDef,





    OpName,



    OpInverse,
};




class ArgsManager {
public:


    ArgsManager(const OCVec& oc, ZAM_InstClass ic);




    string Decls() const { return full_decl; }




    string Params() const { return full_params; }


    const string& NthParam(int n) const { return params[n]; }


    int NumParams() const { return static_cast<int>(args.size()); }

private:



    void Differentiate();



    static std::unordered_map<ZAM_OperandClass, std::pair<const char*, const char*>> oc_to_args;





    struct Arg {
        string decl_name;
        string decl_type;
        string param_name;
    };



    vector<Arg> args;


    vector<string> params;


    string full_decl;
    string full_params;
};




class ZAMGen;

class ZAM_OpTemplate {
public:


    ZAM_OpTemplate(ZAMGen* _g, string _base_name);
    virtual ~ZAM_OpTemplate() {}




    void Build();



    virtual void Instantiate();


    const string& BaseName() const { return base_name; }





    const string& CanonicalName() const { return cname; }



    const string& GetOp1Flavor() const { return op1_flavor; }


    bool HasSideEffects() const { return has_side_effects; }



    void SetIsPredicate() { is_predicate = true; }
    bool IsPredicate() const { return is_predicate; }


    bool HasInverseOp() const { return ! inverse_op_name.empty(); }
    void SetInverseOp(string inv_op) { inverse_op_name = std::move(inv_op); }
    const string& InverseOp() const { return inverse_op_name; }




    virtual int Arity() const { return 0; }

protected:

    void InstantiatePredicate();


    const OCVec& OperandClasses() const { return op_classes; }



    void SetOp1Flavor(string fl) { op1_flavor = fl; }



    void SetTypeParam(int param) { type_param = param; }
    const auto& GetTypeParam() const { return type_param; }



    void SetType2Param(int param) { type2_param = param; }
    const auto& GetType2Param() const { return type2_param; }



    void SetAssignVal(string _av) { av = _av; }
    bool HasAssignVal() const { return ! av.empty(); }
    const string& GetAssignVal() const { return av; }



    void AddEval(string line) { eval += line; }
    bool HasEval() const { return ! eval.empty(); }
    const string& GetEval() const { return eval; }



    void SetCustomMethod(string cm) { custom_method = SkipWS(cm); }
    bool HasCustomMethod() const { return ! custom_method.empty(); }
    const string& GetCustomMethod() const { return custom_method; }


    void SetPostMethod(string cm) { post_method = SkipWS(cm); }
    bool HasPostMethod() const { return ! post_method.empty(); }
    const string& GetPostMethod() const { return post_method; }








    virtual bool IncludesFieldOp() const { return false; }
    virtual bool IsConditionalOp() const { return false; }
    virtual bool IsInternalOp() const { return false; }
    virtual bool IsAssignOp() const { return false; }
    virtual bool IsFieldOp() const { return false; }




    bool NoEval() const { return no_eval; }
    void SetNoEval() { no_eval = true; }



    bool NoConst() const { return no_const; }
    void SetNoConst() { no_const = true; }


    bool IncludesVectorOp() const { return includes_vector_op; }
    void SetIncludesVectorOp() { includes_vector_op = true; }



    void SetHasSideEffects() { has_side_effects = true; }




    bool HasAssignmentLess() const { return ! assignment_less_op.empty(); }
    void SetAssignmentLess(string op, string op_class) {
        assignment_less_op = std::move(op);
        assignment_less_op_class = std::move(op_class);
    }
    const string& AssignmentLessOp() const { return assignment_less_op; }
    const string& AssignmentLessOpClass() const { return assignment_less_op_class; }



    void UnaryInstantiate();







    virtual void Parse(const string& attr, const string& line, const Words& words);


    OCVec ParseClass(const string& spec) const;



    string GatherEval();



    int ExtractTypeParam(const string& arg);




    void InstantiateOp(const OCVec& oc, bool do_vec);




    void InstantiateOp(const string& m, const OCVec& oc, ZAM_InstClass zc);


    void GenAssignmentlessVersion(const string& op);





    void InstantiateMethod(const string& m, const string& suffix, const OCVec& oc, ZAM_InstClass zc);




    void InstantiateMethodCore(const OCVec& oc, const string& suffix, ZAM_InstClass zc);




    virtual void BuildInstruction(const OCVec& oc, const string& params, const string& suffix, ZAM_InstClass zc);



    string ExpandParams(const OCVec& oc, string eval, const vector<string>& accessors) const;
    string ExpandParams(const OCVec& oc, string eval) const {
        vector<string> no_accessors;
        return ExpandParams(oc, std::move(eval), no_accessors);
    }



    virtual void InstantiateEval(const OCVec& oc, const string& suffix, ZAM_InstClass zc);



    void GenEval(EmitTarget et, const string& oc_str, const string& op_suffix, const string& eval, ZAM_InstClass zc);



    void GenDesc(const string& op_code, const string& oc_str, const string& eval);



    void StartDesc(const string& op_code, const string& oc_str);


    void EndDesc();



    void InstantiateAssignOp(const OCVec& oc, const string& suffix);




    void GenAssignOpCore(const OCVec& oc, const string& eval, const string& accessor, bool is_managed);


    void GenAssignOpValCore(const OCVec& oc, const string& eval, const string& accessor, bool is_managed);



    string MethodName(const OCVec& oc) const;


    string MethodDeclare(const OCVec& oc, ZAM_InstClass zc);



    string OpSuffix(const OCVec& oc) const;



    string SkipWS(const string& s) const;


    void EmitTo(EmitTarget et) { curr_et = et; }


    void Emit(const string& s);


    void EmitUp(const string& s) {
        IndentUp();
        Emit(s);
        IndentDown();
    }


    void EmitNoNL(const string& s);



    void NL() { Emit(""); }



    void IndentUp();
    void IndentDown();
    void BeginBlock() {
        IndentUp();
        Emit("{");
    }
    void EndBlock() {
        Emit("}");
        IndentDown();
    }



    void StartString();
    void EndString();


    void Gripe(const char* msg) const;
    void Gripe(string msg, string addl) const;



    static std::unordered_map<ZAM_OperandClass, char> oc_to_char;


    ZAMGen* g;


    string base_name;
    string cname;



    InputLoc op_loc;


    EmitTarget curr_et = None;




    OCVec op_classes;


    vector<OCVec> op_classes_vec;



    vector<ZAM_Type> op_types;





    vector<string> accessors;


    string op1_flavor = "OP1_WRITE";



    std::optional<int> type_param;
    std::optional<int> type2_param;



    string av;


    string eval;


    string post_eval;


    string custom_method;



    string post_method;



    bool no_eval = false;



    bool no_const = false;


    bool includes_vector_op = false;


    bool has_side_effects = false;





    bool is_predicate = false;




    string assignment_less_op;
    string assignment_less_op_class;


    string inverse_op_name;
};


class ZAM_UnaryOpTemplate : public ZAM_OpTemplate {
public:
    ZAM_UnaryOpTemplate(ZAMGen* _g, string _base_name) : ZAM_OpTemplate(_g, _base_name) {}

protected:
    void Instantiate() override;
};



class ZAM_DirectUnaryOpTemplate : public ZAM_OpTemplate {
public:
    ZAM_DirectUnaryOpTemplate(ZAMGen* _g, string _base_name, string _direct)
        : ZAM_OpTemplate(_g, _base_name), direct(_direct) {}

protected:
    void Instantiate() override;

private:

    string direct;
};




class EvalInstance {
public:







    EvalInstance(ZAM_Type lhs_et, ZAM_Type op1_et, ZAM_Type op2_et, string eval, bool is_def);




    string LHSAccessor(bool is_ptr = false) const;


    string Op1Accessor(bool is_ptr = false) const { return Accessor(op1_et, is_ptr); }
    string Op2Accessor(bool is_ptr = false) const { return Accessor(op2_et, is_ptr); }


    string Accessor(ZAM_Type zt, bool is_ptr = false) const;



    string OpMarker() const;

    const string& Eval() const { return eval; }
    bool IsDefault() const { return is_def; }

    ZAM_Type LHS_ET() const { return lhs_et; }
    ZAM_Type Op1_ET() const { return op1_et; }
    ZAM_Type Op2_ET() const { return op2_et; }

private:
    ZAM_Type lhs_et;
    ZAM_Type op1_et;
    ZAM_Type op2_et;
    string eval;
    bool is_def;
};


class ZAM_ExprOpTemplate : public ZAM_OpTemplate {
public:
    ZAM_ExprOpTemplate(ZAMGen* _g, string _base_name);

    int HasExplicitResultType() const { return explicit_res_type; }
    void SetHasExplicitResultType() { explicit_res_type = true; }

    void AddExprType(ZAM_Type zt) { expr_types.insert(zt); }
    const std::unordered_set<ZAM_Type>& ExprTypes() const { return expr_types; }

    void AddEvalSet(ZAM_Type zt, string ev) { eval_set[zt] += ev; }
    void AddEvalSet(ZAM_Type et1, ZAM_Type et2, string ev) { eval_mixed_set[et1][et2] += ev; }

    bool IncludesFieldOp() const override { return includes_field_op; }
    void SetIncludesFieldOp() { includes_field_op = true; }

    bool HasPreCheck() const { return ! pre_check.empty(); }
    void SetPreCheck(string pe) { pre_check = SkipWS(pe); }
    const string& GetPreCheck() const { return pre_check; }

    bool HasPreCheckAction() const { return ! pre_check_action.empty(); }
    void SetPreCheckAction(string pe) { pre_check_action = SkipWS(pe); }
    const string& GetPreCheckAction() const { return pre_check_action; }

protected:




    virtual const char* VecEvalRE(bool have_target) const { return have_target ? "$$$$ = ZVal($1)" : "ZVal($&)"; }

    void Parse(const string& attr, const string& line, const Words& words) override;
    void Instantiate() override;



    void InstantiateC1(const OCVec& ocs, size_t arity);
    void InstantiateC2(const OCVec& ocs, size_t arity);
    void InstantiateC3(const OCVec& ocs);


    void InstantiateV(const OCVec& ocs);




    void DoVectorCase(const string& m, const string& args);



    void BuildInstructionCore(const string& params, const string& suffix, ZAM_InstClass zc);



    void GenMethodTest(ZAM_Type et1, ZAM_Type et2, const string& params, const string& suffix, bool do_else,
                       ZAM_InstClass zc);

    void InstantiateEval(const OCVec& oc, const string& suffix, ZAM_InstClass zc) override;

private:

    std::unordered_set<ZAM_Type> expr_types;


    std::unordered_map<ZAM_Type, string> eval_set;



    std::unordered_map<ZAM_Type, std::unordered_map<ZAM_Type, string>> eval_mixed_set;




    bool includes_field_op = false;


    string pre_check;



    string pre_check_action;



    bool explicit_res_type = false;
};


class ZAM_UnaryExprOpTemplate : public ZAM_ExprOpTemplate {
public:
    ZAM_UnaryExprOpTemplate(ZAMGen* _g, string _base_name) : ZAM_ExprOpTemplate(_g, _base_name) {}

    bool IncludesFieldOp() const override { return ExprTypes().count(ZAM_TYPE_NONE) == 0; }

    int Arity() const override { return 1; }

protected:
    void Parse(const string& attr, const string& line, const Words& words) override;
    void Instantiate() override;

    void BuildInstruction(const OCVec& oc, const string& params, const string& suffix, ZAM_InstClass zc) override;
};



class ZAM_AssignOpTemplate : public ZAM_UnaryExprOpTemplate {
public:
    ZAM_AssignOpTemplate(ZAMGen* _g, string _base_name);

    bool IsAssignOp() const override { return true; }
    bool IncludesFieldOp() const override { return false; }
    bool IsFieldOp() const override { return field_op; }
    void SetFieldOp() { field_op = true; }

protected:
    void Parse(const string& attr, const string& line, const Words& words) override;
    void Instantiate() override;

private:
    bool field_op = false;
};


class ZAM_BinaryExprOpTemplate : public ZAM_ExprOpTemplate {
public:
    ZAM_BinaryExprOpTemplate(ZAMGen* _g, string _base_name) : ZAM_ExprOpTemplate(_g, _base_name) {}

    bool IncludesFieldOp() const override { return true; }

    int Arity() const override { return 2; }

protected:
    void Instantiate() override;

    void BuildInstruction(const OCVec& oc, const string& params, const string& suffix, ZAM_InstClass zc) override;

    void GenerateSecondTypeVars(const OCVec& oc, ZAM_InstClass zc);
};


class ZAM_RelationalExprOpTemplate : public ZAM_BinaryExprOpTemplate {
public:
    ZAM_RelationalExprOpTemplate(ZAMGen* _g, string _base_name) : ZAM_BinaryExprOpTemplate(_g, _base_name) {}

    bool IncludesFieldOp() const override { return false; }
    bool IsConditionalOp() const override { return true; }

protected:
    const char* VecEvalRE(bool have_target) const override {
        if ( have_target )
            return "$$$$ = ZVal(static_cast<zeek_int_t>($1))";
        else
            return "ZVal(static_cast<zeek_int_t>($&))";
    }

    void Instantiate() override;

    void BuildInstruction(const OCVec& oc, const string& params, const string& suffix, ZAM_InstClass zc) override;
};



class ZAM_InternalOpTemplate : public ZAM_OpTemplate {
public:
    ZAM_InternalOpTemplate(ZAMGen* _g, string _base_name) : ZAM_OpTemplate(_g, _base_name) {}

    bool IsInternalOp() const override { return true; }

protected:
    void Parse(const string& attr, const string& line, const Words& words) override;

private:
    void ParseCall(const string& line, const Words& words);



    bool is_indirect_call = false;


    bool is_local_indirect_call = false;
};


class ZAM_InternalAssignOpTemplate : public ZAM_InternalOpTemplate {
public:
    ZAM_InternalAssignOpTemplate(ZAMGen* _g, string _base_name) : ZAM_InternalOpTemplate(_g, _base_name) {}

    bool IsAssignOp() const override { return true; }
};




class TemplateInput {
public:

    TemplateInput(FILE* _f, const char* _prog_name, const char* _file_name) : f(_f), prog_name(_prog_name) {
        loc.file_name = _file_name;
    }

    const InputLoc& CurrLoc() const { return loc; }




    bool ScanLine(string& line);



    Words SplitIntoWords(const string& line) const;


    string SkipWords(const string& line, int n) const;



    void PutBack(const string& line) { put_back = line; }


    [[noreturn]] void Gripe(const char* msg, const string& input) const;
    [[noreturn]] void Gripe(const char* msg, const InputLoc& loc) const;

private:
    string put_back;

    FILE* f;
    const char* prog_name;
    InputLoc loc;
};



class ZAMGen {
public:
    ZAMGen(int argc, char** argv);




    void ReadMacro(const string& line);


    void GenMacros();




    string GenOpCode(const ZAM_OpTemplate* op_templ, const string& suffix, ZAM_InstClass zc = ZIC_REGULAR);



    const InputLoc& CurrLoc() const { return ti->CurrLoc(); }
    bool ScanLine(string& line) { return ti->ScanLine(line); }
    Words SplitIntoWords(const string& line) const { return ti->SplitIntoWords(line); }
    string SkipWords(const string& line, int n) const { return ti->SkipWords(line, n); }
    void PutBack(const string& line) { ti->PutBack(line); }


    void Emit(EmitTarget et, const string& s);

    void IndentUp() { ++indent_level; }
    void IndentDown() { --indent_level; }
    void StartString() { string_lit = true; }
    void EndString() { string_lit = false; }
    void SetNoNL(bool _no_NL) { no_NL = _no_NL; }

    [[noreturn]] void Gripe(const char* msg, const string& input) const { ti->Gripe(msg, input); }
    [[noreturn]] void Gripe(const char* msg, const InputLoc& loc) const { ti->Gripe(msg, loc); }

private:



    void InitEmitTargets();
    void InitSwitch(EmitTarget et, string desc);



    void CloseEmitTargets();
    void FinishSwitches();


    void GenInverseMappings();



    void ValidateInverseOps();




    bool ParseTemplate();


    std::unordered_map<EmitTarget, FILE*> gen_files;



    std::unordered_map<EmitTarget, string> switch_targets;


    std::unique_ptr<TemplateInput> ti;


    vector<std::shared_ptr<ZAM_OpTemplate>> templates;


    vector<vector<string>> macros;


    std::unordered_map<string, std::shared_ptr<ZAM_OpTemplate>> name_to_template;



    std::unordered_map<string, string> inverse_mappings;



    std::unordered_set<string> generated_opcodes;




    int indent_level = 0;


    bool string_lit = false;


    bool no_NL = false;
};
