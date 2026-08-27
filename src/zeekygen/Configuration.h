

#pragma once

#include <ctime>
#include <string>
#include <vector>

#include "zeek/zeekygen/Target.h"

namespace zeek::zeekygen::detail {

class Info;







class Config {
public:






    explicit Config(std::string file, const std::string& delim = "\t");




    ~Config();





    void FindDependencies(const std::vector<Info*>& infos);




    void GenerateDocs() const;





    time_t GetModificationTime() const;

private:
    std::string file;
    std::vector<Target*> targets;
    TargetFactory target_factory;
};

}
