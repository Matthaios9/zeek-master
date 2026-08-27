

#pragma once

#include <string>
#include <vector>

#include "zeek/plugin/Component.h"

namespace zeek::iosource {

class IOSource;
class PktSrc;
class PktDumper;




class Component : public plugin::Component {
public:
    using factory_callback = IOSource* (*)();







    explicit Component(const std::string& name);

protected:








    Component(plugin::component::Type type, const std::string& name);
};




class PktSrcComponent : public Component {
public:



    enum InputType : uint8_t {
        LIVE,
        TRACE,
        BOTH
    };

    using factory_callback = PktSrc* (*)(const std::string& path, bool is_live);

















    PktSrcComponent(const std::string& name, const std::string& prefixes, InputType type, factory_callback factory,
                    std::vector<uint32_t> magic_nums = {});




    const std::vector<std::string>& Prefixes() const;




    bool HandlesPrefix(const std::string& prefix) const;




    bool HandlesMagicNumber(uint32_t magic_num) const;





    bool DoesLive() const;





    bool DoesTrace() const;




    factory_callback Factory() const;





    void DoDescribe(ODesc* d) const override;

private:
    std::vector<std::string> prefixes;
    InputType type;
    factory_callback factory;
    std::vector<uint32_t> magic_nums;
};







class PktDumperComponent : public plugin::Component {
public:
    using factory_callback = PktDumper* (*)(const std::string& path, bool append);




    PktDumperComponent(const std::string& name, const std::string& prefixes, factory_callback factory);




    const std::vector<std::string>& Prefixes() const;




    bool HandlesPrefix(const std::string& prefix) const;




    factory_callback Factory() const;





    void DoDescribe(ODesc* d) const override;

private:
    std::vector<std::string> prefixes;
    factory_callback factory;
};

}
