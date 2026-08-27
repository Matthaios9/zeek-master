







void CompileFunc(const FuncInfo& func);
void CompileLambda(const LambdaExpr* l, const ProfileFunc* pf);



void GenInvokeBody(const std::string& fname, const TypePtr& t, const std::string& args) {
    GenInvokeBody(fname + "(" + args + ")", t);
}
void GenInvokeBody(const std::string& call, const TypePtr& t);



void DefineBody(const FuncTypePtr& ft, const ProfileFunc* pf, const std::string& fname, const StmtPtr& body,
                FunctionFlavor flavor);



void TranslateAnyParams(const FuncTypePtr& ft, const ProfileFunc* pf);



void InitializeEvents(const ProfileFunc* pf);



void DeclareLocals(const ProfileFunc* func);


std::string BodyName(const FuncInfo& func);


std::string GenArgs(const RecordTypePtr& params, const Expr* e);




std::unordered_map<std::string, std::string> compiled_simple_funcs;


std::unordered_map<const Stmt*, std::string> body_names;

struct BodyInfo {
    p_hash_type hash = 0;
    int priority = 0;
    const Location* loc = nullptr;
    std::string module;
    std::vector<std::string> groups;
};


std::unordered_map<std::string, BodyInfo> body_info;


std::unordered_map<std::string, std::vector<std::string>> body_events;


FuncTypePtr func_type;


TypePtr ret_type;


std::string body_name;
