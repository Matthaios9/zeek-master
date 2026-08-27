






public:






std::shared_ptr<CPP_InitInfo> RegisterAttributes(const AttributesPtr& attrs);



int AttributesOffset(const AttributesPtr& attrs) { return GI_Offset(RegisterAttributes(attrs)); }


std::shared_ptr<CPP_InitInfo> RegisterAttr(const AttrPtr& attr);




auto& ProcessedAttr() const { return processed_attr; }

private:








void BuildAttrs(const AttributesPtr& attrs, std::string& attr_tags, std::string& attr_vals);



static const char* AttrName(AttrTag t);


CPPTracker<Attributes> attributes = {"attrs", false};



std::unordered_map<const Attributes*, std::shared_ptr<CPP_InitInfo>> processed_attrs;
std::unordered_map<const Attr*, std::shared_ptr<CPP_InitInfo>> processed_attr;
