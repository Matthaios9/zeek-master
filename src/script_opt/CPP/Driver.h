






void Compile(bool report_uncompilable);






bool AnalyzeFuncBody(FuncInfo& fi, std::unordered_set<std::string>& filenames_reported_as_skipped,
                     std::unordered_set<const Type*>& rep_types, bool report_uncompilable);



void GenProlog();












std::shared_ptr<CPP_InitsInfo> CreateConstInitInfo(const char* tag, const char* type, const char* c_type);



std::shared_ptr<CPP_InitsInfo> CreateCompoundInitInfo(const char* tag, const char* type);



std::shared_ptr<CPP_InitsInfo> CreateCustomInitInfo(const char* tag, const char* type);




std::shared_ptr<CPP_InitsInfo> RegisterInitInfo(const char* tag, const char* type, std::shared_ptr<CPP_InitsInfo> gi);




void RegisterCompiledBody(const std::string& f);



void GenEpilog();



void GenCPPDynStmt();


void GenLoadBiFs();



void GenFinishInit();


void GenRegisterBodies();

public:

bool TargetingStandalone() const { return standalone; }

private:




bool IsCompilable(const FuncInfo& func, const char** reason = nullptr);


std::vector<FuncInfo>& funcs;


std::shared_ptr<ProfileFuncs> pfs;


std::unordered_map<StmtPtr, std::shared_ptr<ProfileFunc>> body_profiles;








std::unordered_set<std::string> compilable_funcs;



std::unordered_set<std::string> not_fully_compilable;


std::unordered_map<std::string, std::string> hashed_funcs;


bool standalone = false;


bool skipped_uncompilable_func = false;





p_hash_type total_hash = 0;
