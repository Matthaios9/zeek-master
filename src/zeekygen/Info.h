

#pragma once

#include <ctime>
#include <string>

namespace zeek::zeekygen::detail {




class Info {
public:



    Info() = default;




    virtual ~Info() = default;




    time_t GetModificationTime() const { return DoGetModificationTime(); }




    std::string Name() const { return DoName(); }








    std::string ReStructuredText(bool roles_only = false) const { return DoReStructuredText(roles_only); }





    void InitPostScript() { DoInitPostScript(); }

private:
    virtual time_t DoGetModificationTime() const = 0;

    virtual std::string DoName() const = 0;

    virtual std::string DoReStructuredText(bool roles_only) const = 0;

    virtual void DoInitPostScript() {}
};

}
