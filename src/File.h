

#pragma once

#include <fcntl.h>
#include <list>
#include <string>
#include <utility>

#include "zeek/Val.h"
#include "zeek/util.h"

namespace zeek {

namespace detail {

class PrintStmt;
class Attributes;

extern void do_print_stmt(const std::vector<ValPtr>& vals);

}

class RecordVal;
class Type;
using TypePtr = IntrusivePtr<Type>;

class File;
using FilePtr = IntrusivePtr<File>;

class File final : public Obj {
public:
    explicit File(FILE* arg_f);
    File(FILE* arg_f, const char* filename, const char* access);
    File(const char* filename, const char* access);
    ~File() override;

    const char* Name() const;


    bool Write(const char* data, int len = 0);

    void Flush() { fflush(f); }

    FILE* Seek(long position);

    void SetBuf(bool buffered);

    const TypePtr& GetType() const { return t; }




    bool IsOpen() const { return is_open; }



    bool Close();

    void Describe(ODesc* d) const override;


    RecordVal* Rotate();


    void SetAttrs(detail::Attributes* attrs);


    double Size();


    static void CloseOpenFiles();


    static FilePtr Get(const char* name);

    void EnableRawOutput() { raw_output = true; }
    bool IsRawOutput() const { return raw_output; }

protected:
    friend void detail::do_print_stmt(const std::vector<ValPtr>& vals);

    File() { Init(); }
    void Init();






    bool Open(FILE* f = nullptr, const char* mode = nullptr);

    void Unlink();





    FILE* FileHandle();


    void RaiseOpenEvent();

    FILE* f = nullptr;
    TypePtr t;
    char* name = nullptr;
    char* access = nullptr;
    detail::Attributes* attrs = nullptr;
    double open_time = 0.0;
    bool is_open = false;
    bool buffered = false;
    bool raw_output = false;

    static constexpr int MIN_BUFFER_SIZE = 1024;
};

}
