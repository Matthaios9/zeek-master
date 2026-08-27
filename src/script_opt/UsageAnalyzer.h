




#pragma once

#include "zeek/Traverse.h"
#include "zeek/script_opt/ScriptOpt.h"

namespace zeek::detail {

class UsageAnalyzer : public TraversalCallback {
public:

    UsageAnalyzer(std::vector<FuncInfo>& funcs);

private:








    void FindSeeds(IDSet& seeds) const;



    const Func* GetFuncIfAny(const IDPtr& id) const;



    void FullyExpandReachables();



    bool ExpandReachables(const IDSet& curr_r);



    void Expand(const IDPtr& f);


    TraversalCode PreID(const ID* id) override;



    TraversalCode PreType(const Type* t) override;



    IDSet reachables;




    IDSet new_reachables;







    IDSet analyzed_IDs;


    TypeSet analyzed_types;
};



extern void register_new_event(const IDPtr& id);

}
