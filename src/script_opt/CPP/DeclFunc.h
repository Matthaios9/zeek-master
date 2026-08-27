








void DeclareFunc(const FuncInfo& func);


void DeclareLambda(const LambdaExpr* l, const ProfileFunc* pf);




















void CreateFunction(const FuncTypePtr& ft, const ProfileFunc* pf, const std::string& fname, const StmtPtr& body,
                    int priority, const LambdaExpr* l, FunctionFlavor flavor,
                    const std::forward_list<EventGroupPtr>* e_g = nullptr);


void DeclareSubclass(const FuncTypePtr& ft, const ProfileFunc* pf, const std::string& fname, const std::string& args);


void DeclareDynCPPStmt();



void BuildLambda(const FuncTypePtr& ft, const ProfileFunc* pf, const std::string& fname, const StmtPtr& body,
                 const LambdaExpr* l);




std::string BindArgs(const FuncTypePtr& ft);



std::string ParamDecl(const FuncTypePtr& ft, const ProfileFunc* pf);



void GatherParamTypes(std::vector<std::string>& p_types, const FuncTypePtr& ft, const ProfileFunc* pf);


void GatherParamNames(std::vector<std::string>& p_names, const FuncTypePtr& ft, const ProfileFunc* pf);




IDPtr FindParam(int i, const ProfileFunc* pf);


struct DispatchInfo {
    std::string cast;
    std::string args;
    bool is_hook;
    TypePtr yield;
};



std::vector<DispatchInfo> func_casting_glue;



std::unordered_map<std::string, int> casting_index;


std::unordered_map<std::string, std::string> func_index;



std::unordered_map<std::string, std::string> compiled_func_to_zeek_func;


const IDPList* lambda_ids = nullptr;




std::unordered_map<IDPtr, std::string> lambda_names;


IDSet params;


bool in_hook = false;
