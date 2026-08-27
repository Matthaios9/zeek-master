





public:





std::shared_ptr<CPP_InitInfo> RegisterType(const TypePtr& t);

private:



bool IsNativeType(const TypePtr& t) const;



std::string NativeToGT(const std::string& expr, const TypePtr& t, GenType gt);



std::string GenericValPtrToGT(const std::string& expr, const TypePtr& t, GenType gt);



std::string GenTypeName(const Type* t);
std::string GenTypeName(const TypePtr& t) { return GenTypeName(t.get()); }




const Type* TypeRep(const Type* t) { return pfs->TypeRep(t); }
const Type* TypeRep(const TypePtr& t) { return TypeRep(t.get()); }


static const char* TypeTagName(TypeTag tag);
const char* TypeName(const TypePtr& t);
const char* FullTypeName(const TypePtr& t);
const char* TypeType(const TypePtr& t);


const char* NativeAccessor(const TypePtr& t);



const char* IntrusiveVal(const TypePtr& t);


CPPTracker<Type> types = {"types", true};




std::unordered_map<const Type*, std::shared_ptr<CPP_InitInfo>> processed_types;
