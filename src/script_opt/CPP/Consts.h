








public:








std::shared_ptr<CPP_InitInfo> RegisterConstant(const ValPtr& vp, int& consts_offset);
std::shared_ptr<CPP_InitInfo> RegisterConstant(const ValPtr& vp) {
    [[maybe_unused]] int consts_offset;
    return RegisterConstant(vp, consts_offset);
}

private:

std::unordered_map<const ConstExpr*, std::string> const_exprs;



std::unordered_map<const Val*, std::shared_ptr<CPP_InitInfo>> const_vals;



std::unordered_map<const Val*, int> const_offsets;




std::unordered_map<std::string, std::shared_ptr<CPP_InitInfo>> constants;
std::unordered_map<std::string, int> constants_offsets;


std::vector<ValPtr> cv_indices;




std::unordered_map<TypeTag, std::shared_ptr<CPP_InitsInfo>> const_info;





std::vector<std::pair<TypeTag, int>> consts;
