

#pragma once

#include <unistd.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <string>




void appendf(std::string& out, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
void vappendf(std::string& out, const char* fmt, va_list ap);

enum builtin_func_arg_type : uint8_t {

#define DEFINE_BIF_TYPE(id, bif_type, bro_type, c_type, c_type_smart, accessor, accessor_smart, cast_smart,            \
                        constructor, ctor_smart, native_return_type, native_to_val)                                    \
    id,
#include "bif_type.def"
#undef DEFINE_BIF_TYPE
};




struct bif_type_info {
    const char* type_enum;
    const char* bif_type;
    const char* zeek_type;
    const char* c_type;
    const char* c_type_smart;
    const char* accessor;
    const char* accessor_smart;
    const char* cast_smart;
    const char* constructor;
    const char* ctor_smart;
    const char* native_return_type;
    const char* native_to_val;
};

extern const bif_type_info bif_types[];



int get_type_index(const char* name);

class BuiltinFuncArg final {
public:
    BuiltinFuncArg(const char* arg_name, int arg_type);
    BuiltinFuncArg(const char* arg_name, const char* arg_type_str, const char* arg_attr_str = "");

    void SetAttrStr(const char* arg_attr_str) { attr_str = arg_attr_str; };

    const char* Name() const { return name; }
    int Type() const { return type; }





    const char* NativeReturnType() const;



    const char* NativeToVal() const;

    void PrintZeek(std::string& out);
    void PrintCDef(std::string& out, int n, bool runtime_type_check);
    void PrintCArg(std::string& out, int n);
    void PrintValConstructor(std::string& out);



    void PrintCImplParam(std::string& out);
    void PrintCImplCallArg(std::string& out);




    void PrintZeek(FILE* fp);
    void PrintCDef(FILE* fp, int n, bool runtime_type_check);
    void PrintCArg(FILE* fp, int n);
    void PrintValConstructor(FILE* fp);
    void PrintCImplParam(FILE* fp);
    void PrintCImplCallArg(FILE* fp);

private:
    const char* name;
    int type;
    const char* type_str;
    const char* attr_str;
};
