






public:



static bool IsSimpleInitExpr(const ExprPtr& e);



int TypeOffset(const TypePtr& t) { return GI_Offset(RegisterType(t)); }
int TypeCohort(const TypePtr& t) { return GI_Cohort(RegisterType(t)); }
int TypeFinalCohort(const TypePtr& t) { return GI_FinalCohort(RegisterType(t)); }













std::shared_ptr<CPP_InitInfo> RegisterInitExpr(const ExprPtr& e);



int TrackString(const std::string& s) {
    auto ts = tracked_strings.find(s);
    if ( ts != tracked_strings.end() )
        return ts->second;

    int offset = ordered_tracked_strings.size();
    tracked_strings[s] = offset;
    ordered_tracked_strings.emplace_back(s);

    return offset;
}



int TrackHash(p_hash_type h) {
    auto th = tracked_hashes.find(h);
    if ( th != tracked_hashes.end() )
        return th->second;

    int offset = ordered_tracked_hashes.size();
    tracked_hashes[h] = offset;
    ordered_tracked_hashes.emplace_back(h);

    return offset;
}

private:


void GenInitExpr(const std::shared_ptr<CallExprInitInfo>& ce_init);


std::string InitExprName(const ExprPtr& e);



int GI_Offset(const std::shared_ptr<CPP_InitInfo>& gi) const { return gi ? gi->Offset() : -1; }
int GI_Cohort(const std::shared_ptr<CPP_InitInfo>& gi) const { return gi ? gi->InitCohort() : 0; }
int GI_FinalCohort(const std::shared_ptr<CPP_InitInfo>& gi) const { return gi ? gi->FinalInitCohort() : 0; }




void InitializeFieldMappings();


void InitializeEnumMappings();


void InitializeBiFs();


void InitializeStrings();


void InitializeHashes();


void InitializeConsts();



void InitializeGlobal(const IDPtr& g);



void InitializeGlobals();


void GenInitHook();


void GenStandaloneActivation();



void GenLoad();



std::unordered_map<std::string, std::string> BiFs;



CPPTracker<Expr> init_exprs = {"gen_init_expr", false};


std::unordered_map<std::string, int> tracked_strings;



std::vector<std::string> ordered_tracked_strings;


std::vector<p_hash_type> ordered_tracked_hashes;
std::unordered_map<p_hash_type, int> tracked_hashes;
