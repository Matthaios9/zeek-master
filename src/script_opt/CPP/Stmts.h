







void GenStmt(const StmtPtr& s) { GenStmt(s.get()); }
void GenStmt(const Stmt* s);
void GenInitStmt(const InitStmt* init);
void GenIfStmt(const IfStmt* i);
void GenWhileStmt(const WhileStmt* w);
void GenReturnStmt(const ReturnStmt* r);
void GenEventStmt(const EventStmt* ev);

void GenSwitchStmt(const SwitchStmt* sw);
void GenTypeSwitchStmt(const Expr* e, const case_list* cases);
void GenTypeSwitchCase(const IDPtr id, int case_offset, bool is_multi);
void GenValueSwitchStmt(const Expr* e, const case_list* cases);

void GenWhenStmt(const WhenStmt* w);
void GenWhenStmt(const WhenInfo* wi, const std::string& when_lambda, const Location* loc,
                 const std::vector<std::string>& local_aggrs);
void GenForStmt(const ForStmt* f);
void GenForOverTable(const ExprPtr& tbl, const IDPtr& value_var, const IDPList* loop_vars);
void GenForOverVector(const ExprPtr& tbl, const IDPtr& value_var, const IDPList* loop_vars);
void GenForOverString(const ExprPtr& str, const IDPList* loop_vars);

void GenAssertStmt(const AssertStmt* a);



int break_level = 0;
