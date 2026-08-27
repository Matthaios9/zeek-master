





ZAMStmt StartingBlock();
ZAMStmt FinishBlock(ZAMStmt start);

bool NullStmtOK() const;

ZAMStmt EmptyStmt();
ZAMStmt ErrorStmt();
ZAMStmt LastInst();


void AddCFT(ZInstI* inst, ControlFlowType cft);



std::unique_ptr<OpaqueVals> BuildVals(const ListExprPtr&);


ZInstAux* InternalBuildVals(const ListExpr* l, int stride = 1);


int InternalAddVal(ZInstAux* zi, int i, Expr* e);




ZAMStmt AddInst(const ZInstI& inst, bool suppress_non_local = false);


const Stmt* LastStmt(const Stmt* s) const;



ZInstI* TopMainInst() { return insts1[top_main_inst]; }
