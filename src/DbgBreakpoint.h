



#pragma once

#include <cstdint>
#include <string>

namespace zeek::detail {

class Stmt;
class ParseLocationRec;

enum BreakCode : uint8_t { BC_NO_HIT, BC_HIT, BC_HIT_AND_DELETE };
class DbgBreakpoint {
    enum Kind : uint8_t { BP_STMT = 0, BP_FUNC, BP_LINE, BP_TIME };

public:
    DbgBreakpoint();
    ~DbgBreakpoint();

    int GetID() const { return BPID; }
    void SetID(int newID) { BPID = newID; }


    bool SetLocation(ParseLocationRec plr, std::string_view loc_str);
    bool SetLocation(Stmt* stmt);
    bool SetLocation(double time);

    bool Reset();


    bool IsTemporary() const { return temporary; }
    void SetTemporary(bool is_temporary) { temporary = is_temporary; }







    BreakCode ShouldBreak(Stmt* s);
    BreakCode ShouldBreak(double t);

    const std::string& GetCondition() const { return condition; }
    bool SetCondition(const std::string& new_condition);

    int GetRepeatCount() const { return repeat_count; }
    bool SetRepeatCount(int count);

    bool IsEnabled() const { return enabled; }
    bool SetEnable(bool do_enable);


    const char* Description() const { return description; }

protected:
    void AddToGlobalMap();
    void RemoveFromGlobalMap();

    void AddToStmt();
    void RemoveFromStmt();

    BreakCode HasHit();
    void PrintHitMsg();

    Kind kind;
    int32_t BPID;

    char description[512];
    std::string function_name;
    const char* source_filename;
    int32_t source_line;
    bool enabled;
    bool temporary;

    Stmt* at_stmt;
    double at_time;


    int32_t repeat_count;
    int32_t hit_count;

    std::string condition;
};

}
