

#pragma once

#include <sys/types.h>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>

#include "zeek/IntrusivePtr.h"
#include "zeek/ZeekString.h"
#include "zeek/util-types.h"

namespace zeek {

class IPAddr;
class IPPrefix;
class File;
class Type;
class Val;

enum DescType : uint8_t {
    DESC_READABLE,
    DESC_BINARY,
};

enum DescStyle : uint8_t {
    STANDARD_STYLE,
    RAW_STYLE,
};

class ODesc {
public:
    explicit ODesc(DescType t = DESC_READABLE, File* f = nullptr);

    ~ODesc();

    bool IsReadable() const { return type == DESC_READABLE; }
    bool IsBinary() const { return type == DESC_BINARY; }

    bool IsShort() const { return is_short; }
    void SetShort() { is_short = true; }
    void SetShort(bool s) { is_short = s; }


    bool WantQuotes() const { return want_quotes; }
    void SetQuotes(bool q) { want_quotes = q; }



    bool WantDeterminism() const { return want_determinism; }
    void SetDeterminism(bool d) { want_determinism = d; }



    bool IncludeStats() const { return include_stats; }
    void SetIncludeStats(bool s) { include_stats = s; }

    DescStyle Style() const { return style; }
    void SetStyle(DescStyle s) { style = s; }

    void SetFlush(bool arg_do_flush) { do_flush = arg_do_flush; }

    void EnableEscaping();
    void EnableUTF8();
    void AddEscapeSequence(const char* s) { escape_sequences.insert(s); }
    void AddEscapeSequence(const char* s, size_t n) { escape_sequences.insert(std::string(s, n)); }
    void AddEscapeSequence(const std::string& s) { escape_sequences.insert(s); }
    void RemoveEscapeSequence(const char* s) { escape_sequences.erase(s); }
    void RemoveEscapeSequence(const char* s, size_t n) { escape_sequences.erase(std::string(s, n)); }
    void RemoveEscapeSequence(const std::string& s) { escape_sequences.erase(s); }

    void PushIndent();
    void PopIndent();
    void PopIndentNoNL();
    int GetIndentLevel() const { return indent_level; }
    void ClearIndentLevel() { indent_level = 0; }

    int IndentSpaces() const { return indent_with_spaces; }
    void SetIndentSpaces(int i) { indent_with_spaces = i; }

    void Add(std::string_view sv) { AddBytes(sv.data(), sv.size()); }
    void Add(const char* s, int do_indent = 1);
    void AddN(const char* s, int len) { AddBytes(s, len); }
    void Add(const std::string& s) { AddBytes(s.data(), s.size()); }
    void Add(int i);
    void Add(uint32_t u);
    void Add(int64_t i);
    void Add(uint64_t u);
    void Add(double d, bool no_exp = false);
    void Add(const IPAddr& addr);
    void Add(const IPPrefix& prefix);


    void AddCS(const char* s);

    void AddBytes(const String* s);

    void Add(const char* s1, const char* s2) {
        Add(s1);
        Add(s2);
    }

    void AddSP(const char* s1, const char* s2) {
        Add(s1);
        AddSP(s2);
    }

    void AddSP(const char* s) {
        Add(s);
        SP();
    }

    void AddCount(zeek_int_t n) {
        if ( ! IsReadable() ) {
            Add(n);
            SP();
        }
    }

    void SP() {
        if ( ! IsBinary() )
            Add(" ", 0);
    }
    void NL() {
        if ( ! IsBinary() && ! is_short )
            Add("\n", 0);
    }


    void AddRaw(const char* s, int len) { AddBytesRaw(s, len); }
    void AddRaw(const std::string& s) { AddBytesRaw(s.data(), s.size()); }


    const char* Description() const { return reinterpret_cast<const char*>(base); }

    const u_char* Bytes() const { return reinterpret_cast<const u_char*>(base); }
    byte_vec TakeBytes() {
        const void* t = base;
        base = nullptr;
        size = 0;




        return reinterpret_cast<byte_vec>(const_cast<void*>(t));
    }

    size_t Size() const { return offset; }

    void Clear();



    bool PushType(const Type* type);
    bool PopType(const Type* type);
    bool FindType(const Type* type);



    bool PushVal(const Val* v);
    bool PopVal(const Val* v);

protected:
    void Indent();

    void AddBytes(const void* bytes, size_t n);
    void AddBytesRaw(const void* bytes, size_t n);


    void Grow(size_t n);












    std::pair<const char*, size_t> FirstEscapeLoc(const char* bytes, size_t n);








    size_t StartsWithEscapeSequence(const char* start, const char* end);

    DescType type;
    DescStyle style;

    void* base;
    size_t offset;
    size_t size;

    bool utf8;
    bool escape;
    bool is_short;
    bool want_quotes;
    bool want_determinism;
    bool do_flush;
    bool include_stats;

    int indent_with_spaces;
    int indent_level;

    using escape_set = std::set<std::string>;
    escape_set escape_sequences;

    File* f;

    std::unordered_set<const Type*> encountered_types;
    std::unordered_set<const Val*> encountered_vals;
};



class Obj;
std::string obj_desc(const Obj* o);
inline std::string obj_desc(const IntrusivePtr<Obj>& o) { return obj_desc(o.get()); }


std::string obj_desc_short(const Obj* o);
inline std::string obj_desc_short(const IntrusivePtr<Obj>& o) { return obj_desc_short(o.get()); }

}
