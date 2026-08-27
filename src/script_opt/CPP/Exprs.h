


















#include <cstdint>

enum GenType : uint8_t {
    GEN_NATIVE,
    GEN_VAL_PTR,
    GEN_DONT_CARE,
};




std::string GenExprs(const Expr* e);





std::string GenListExpr(const Expr* e, GenType gt, bool nested);



std::string GenExpr(const ExprPtr& e, GenType gt, bool top_level = false) { return GenExpr(e.get(), gt, top_level); }
std::string GenExpr(const Expr* e, GenType gt, bool top_level = false);

std::string GenNameExpr(const NameExpr* ne, GenType gt);
std::string GenConstExpr(const ConstExpr* c, GenType gt);
std::string GenAggrAdd(const Expr* e);
std::string GenAggrDel(const Expr* e);
std::string GenIncrExpr(const Expr* e, GenType gt, bool is_incr, bool top_level);
std::string GenCondExpr(const Expr* e, GenType gt);
std::string GenCallExpr(const CallExpr* c, GenType gt, bool top_level);
std::string GenInExpr(const Expr* e, GenType gt);
std::string GenFieldExpr(const FieldExpr* fe, GenType gt);
std::string GenHasFieldExpr(const HasFieldExpr* hfe, GenType gt);
std::string GenIndexExpr(const Expr* e, GenType gt);
std::string GenAssignExpr(const Expr* e, GenType gt, bool top_level);
std::string GenAddToExpr(const Expr* e, GenType gt, bool top_level);
std::string GenRemoveFromExpr(const Expr* e, GenType gt, bool top_level);
std::string GenSizeExpr(const Expr* e, GenType gt);
std::string GenScheduleExpr(const Expr* e);
std::string GenLambdaExpr(const Expr* e);
std::string GenLambdaExpr(const Expr* e, std::string capture_args);
std::string GenIsExpr(const Expr* e, GenType gt);

std::string GenArithCoerceExpr(const Expr* e, GenType gt);
std::string GenRecordCoerceExpr(const Expr* e);
std::string GenTableCoerceExpr(const Expr* e);
std::string GenVectorCoerceExpr(const Expr* e);

std::string GenRecordConstructorExpr(const Expr* e);
std::string GenSetConstructorExpr(const Expr* e);
std::string GenTableConstructorExpr(const Expr* e);
std::string GenVectorConstructorExpr(const Expr* e);


std::string GenVal(const ValPtr& v);


std::string GenUnary(const Expr* e, GenType gt, const char* op, const char* vec_op = nullptr);
std::string GenBinary(const Expr* e, GenType gt, const char* op, const char* vec_op = nullptr);
std::string GenBinarySet(const Expr* e, GenType gt, const char* op);
std::string GenBinaryString(const Expr* e, GenType gt, const char* op);
std::string GenBinaryPattern(const Expr* e, GenType gt, const char* op);
std::string GenBinaryAddr(const Expr* e, GenType gt, const char* op);
std::string GenBinarySubNet(const Expr* e, GenType gt, const char* op);
std::string GenEQ(const Expr* e, GenType gt, const char* op, const char* vec_op);

std::string GenAssign(const ExprPtr& lhs, const ExprPtr& rhs, const std::string& rhs_native,
                      const std::string& rhs_val_ptr, GenType gt, bool top_level);
std::string GenDirectAssign(const ExprPtr& lhs, const std::string& rhs_native, const std::string& rhs_val_ptr,
                            GenType gt, bool top_level);
std::string GenIndexAssign(const ExprPtr& lhs, const ExprPtr& rhs, const std::string& rhs_val_ptr, GenType gt,
                           bool top_level);
std::string GenFieldAssign(const ExprPtr& lhs, const ExprPtr& rhs, const std::string& rhs_native,
                           const std::string& rhs_val_ptr, GenType gt, bool top_level);
std::string GenListAssign(const ExprPtr& lhs, const ExprPtr& rhs);


std::string GenVectorOp(const Expr* e, const std::string& op, const char* vec_op);
std::string GenVectorOp(const Expr* e, const std::string& op1, const std::string& op2, const char* vec_op);





std::string GenLambdaClone(const LambdaExpr* l, bool all_deep);


std::string GenIntVector(const std::vector<int>& vec);








std::string GenField(const ExprPtr& rec, int field);
std::string GenEnum(const TypePtr& et, const ValPtr& ev);



friend class GlobalInitInfo;
int ReadyExpr(const ExprPtr& e);


int ReadyProfile(const std::shared_ptr<ProfileFunc>& pf);


std::unordered_map<IDPtr, int> readied_globals;



int GetFieldMapping(const RecordType* rt, int field);







std::unordered_map<const RecordType*, std::unordered_map<int, int>> record_field_mappings;



int num_rf_mappings = 0;



std::vector<std::pair<int, const TypeDecl*>> field_decls;







std::unordered_map<const EnumType*, std::unordered_map<int, int>> enum_val_mappings;



int num_ev_mappings = 0;


struct EnumMappingInfo {
    int enum_type;
    std::string enum_name;
    bool create_if_missing;
};



std::vector<EnumMappingInfo> enum_names;
