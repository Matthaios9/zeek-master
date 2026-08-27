

#pragma once

#include <list>
#include <map>
#include <string>
#include <utility>

#include "zeek/ID.h"
#include "zeek/StmtBase.h"

namespace zeek::detail {

using ObjPtr = IntrusivePtr<Obj>;




class ScriptCoverageManager {
public:
    ScriptCoverageManager();






    bool IsActive() const { return pf != nullptr; }







    bool ReadStats();










    bool WriteStats();

    void SetDelim(char d) { delim = d; }

    void IncIgnoreDepth() { ignoring++; }
    void DecIgnoreDepth() { ignoring--; }

    void AddStmt(Stmt* s);
    void AddFunction(IDPtr func_id, StmtPtr body);
    void AddConditional(Location cond_loc, std::string_view text, bool was_true);

private:



    const char* pf;




    std::list<StmtPtr> stmts;




    std::list<std::pair<IDPtr, StmtPtr>> func_instances;




    struct Conditional {
        Location loc;
        std::string text;
        bool result;
    };




    std::list<Conditional> cond_instances;





    uint32_t ignoring = 0;




    char delim = '\t';







    std::map<std::pair<std::string, std::string>, uint64_t> usage_map;





    struct canonicalize_desc {
        char delim;

        void operator()(char& c) {
            if ( c == '\n' )
                c = ' ';
            if ( c == delim )
                c = ' ';
        }
    };





    void TrackUsage(const ObjPtr& obj, std::string desc, uint64_t cnt) {
        TrackUsage(obj->GetLocationInfo(), std::move(desc), cnt);
    }
    void TrackUsage(const Location* loc, std::string desc, uint64_t cnt);




    void Report(FILE* f, uint64_t cnt, std::string_view loc, std::string_view desc);
};

extern ScriptCoverageManager script_coverage_mgr;

}
