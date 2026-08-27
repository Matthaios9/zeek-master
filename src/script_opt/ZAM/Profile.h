



#pragma once

#include <memory>
#include <set>
#include <string>

namespace zeek::detail {

class Location;

class ZAMLocInfo {
public:





    ZAMLocInfo(std::string _func_name, std::shared_ptr<Location> _loc, std::shared_ptr<ZAMLocInfo> _parent);

    const std::string& FuncName() const { return func_name; }
    const Location* Loc() const { return loc.get(); }
    std::shared_ptr<Location> LocPtr() const { return loc; }
    std::shared_ptr<ZAMLocInfo> Parent() { return parent; }
    const auto& GetModules() const { return modules; }



    std::string Describe(bool include_lines) const;

private:
    std::string func_name;
    std::set<std::string> modules;
    std::shared_ptr<Location> loc;
    std::shared_ptr<ZAMLocInfo> parent;
};


extern void estimate_ZAM_profiling_overhead();



extern void report_ZOP_profile();

}
