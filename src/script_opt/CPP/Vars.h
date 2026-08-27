





public:


std::shared_ptr<CPP_InitInfo> RegisterGlobal(IDPtr g);

private:





bool CreateGlobal(IDPtr g);



std::shared_ptr<CPP_InitInfo> GenerateGlobalInit(IDPtr g);



void AddBiF(IDPtr b, bool is_var);




bool AddGlobal(const std::string& g, const char* suffix);


void RegisterEvent(std::string ev_name);



bool HasFixedInit(const IDPtr& g) const;



ValPtr GenFixedInit(IDPtr g) const;



const char* IDName(const IDPtr& id) { return IDNameStr(id).c_str(); }
const std::string& IDNameStr(const IDPtr& id);



std::string GlobalName(const std::string& g, const char* suffix) { return Canonicalize(g.c_str()) + "_" + suffix; }



std::string LocalName(const IDPtr& l) const;


std::string CaptureName(const IDPtr& l) const;



std::string Canonicalize(const std::string& name) const;



std::unordered_set<IDPtr> all_accessed_globals;


std::unordered_set<IDPtr> accessed_globals;


std::unordered_set<const LambdaExpr*> accessed_lambdas;


std::unordered_set<std::string> accessed_events;


std::unordered_map<std::string, std::string> globals;


std::set<std::string> standalone_modules;


std::unordered_map<IDPtr, std::string> locals;


std::unordered_map<IDPtr, std::shared_ptr<CPP_InitInfo>> global_gis;


std::unordered_map<std::string, std::string> events;


IDSet global_vars;
