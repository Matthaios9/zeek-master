

#pragma once

#include "zeek/zeek-config.h"

#include <climits>
#include <string>

namespace zeek {

class ODesc;

namespace detail {

class Location final {
public:
    constexpr Location(const char* fname, int line_f, int line_l) noexcept : filename(fname) {
        SetLines(line_f, line_l);
    }

    Location() = default;

    void Describe(ODesc* d) const;

    bool operator==(const Location& l) const;
    bool operator!=(const Location& l) const { return ! (*this == l); }

    const char* FileName() const { return filename; }
    int FirstLine() const { return first_line; }
    int LastLine() const { return last_line; }

    void SetFile(const char* fname) { filename = fname; }
    void SetLine(int line) { SetLines(line, line); }
    constexpr void SetLines(int first, int last) {
        if ( first > last ) {


            auto tmp = first;
            first = last;
            last = tmp;
        }
        first_line = first;
        last_line = last;
    }
    void SetFirstLine(int line) { SetLines(line, last_line); }
    void SetLastLine(int line) { SetLines(first_line, line); }
    void IncrementLine(int incr = 1) {
        first_line += incr;
        last_line += incr;
    }

private:
    const char* filename = nullptr;
    int first_line = 0, last_line = 0;
};

#define YYLTYPE zeek::detail::yyltype
using yyltype = Location;
YYLTYPE GetCurrentLocation();
void SetCurrentLocation(YYLTYPE currloc);


inline constexpr Location no_location("<no location>", 0, 0);


ZEEK_EXTERN_DATA Location start_location;
ZEEK_EXTERN_DATA Location end_location;


inline void set_location(const Location loc) { start_location = end_location = loc; }

inline void set_location(const Location start, const Location end) {
    start_location = start;
    end_location = end;
}


template<typename T, typename U>
T with_location_of(T e, const U& o) {
    e->SetLocationInfo(o->GetLocationInfo());
    return e;
}

}

class Obj {
public:
    Obj() {













        location = nullptr;
        if ( detail::start_location.FirstLine() != 0 )
            SetLocationInfo(&detail::start_location, &detail::end_location);
    }

    virtual ~Obj();


    Obj(const Obj&) = delete;
    Obj& operator=(const Obj&) = delete;




    void Warn(const char* msg, const Obj* obj2 = nullptr, bool pinpoint_only = false,
              const detail::Location* expr_location = nullptr) const;
    void Error(const char* msg, const Obj* obj2 = nullptr, bool pinpoint_only = false,
               const detail::Location* expr_location = nullptr) const;


    [[noreturn]] void BadTag(const char* msg, const char* t1 = nullptr, const char* t2 = nullptr) const;


#define CHECK_TAG(t1, t2, text, tag_to_text_func)                                                                      \
    {                                                                                                                  \
        if ( (t1) != (t2) )                                                                                            \
            BadTag(text, tag_to_text_func(t1), tag_to_text_func(t2));                                                  \
    }

    [[noreturn]] void Internal(const char* msg) const;
    void InternalWarning(const char* msg) const;

    virtual void Describe(ODesc* d) const {  };

    void AddLocation(ODesc* d) const;


    virtual const detail::Location* GetLocationInfo() const { return location ? location : &detail::no_location; }

    virtual bool SetLocationInfo(const detail::Location* loc) { return SetLocationInfo(loc, loc); }


    virtual bool SetLocationInfo(const detail::Location* start, const detail::Location* end);



    virtual void UpdateLocationEndInfo(const detail::Location& end);


    void NotifyPluginsOnDtor() { notify_plugins = true; }

    int RefCnt() const { return ref_cnt; }



    class SuppressErrors {
    public:
        SuppressErrors() { ++Obj::suppress_errors; }
        ~SuppressErrors() { --Obj::suppress_errors; }
    };

    void Print() const;

protected:
    detail::Location* location;

private:
    friend class SuppressErrors;

    void DoMsg(ODesc* d, const char s1[], const Obj* obj2 = nullptr, bool pinpoint_only = false,
               const detail::Location* expr_location = nullptr) const;
    void PinPoint(ODesc* d, const Obj* obj2 = nullptr, bool pinpoint_only = false) const;

    friend inline void Ref(Obj* o);
    friend inline void Unref(Obj* o);

    int ref_cnt = 1;
    bool notify_plugins = false;



    static int suppress_errors;
};



inline void Error(const Obj* o, const char* msg) { o->Error(msg); }

[[noreturn]] extern void bad_ref(int type);

inline void Ref(Obj* o) {
    if ( ++(o->ref_cnt) <= 1 )
        bad_ref(0);
    if ( o->ref_cnt == INT_MAX )
        bad_ref(1);
}

inline void Unref(Obj* o) {
    if ( o && --o->ref_cnt <= 0 ) {
        if ( o->ref_cnt < 0 )
            bad_ref(2);
        delete o;



    }
}


extern void obj_delete_func(void* v);

}
