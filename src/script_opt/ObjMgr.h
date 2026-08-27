














#pragma once

#include <unordered_map>

#include "zeek/IntrusivePtr.h"
#include "zeek/Obj.h"

namespace zeek::detail {




class ObjWrapper {
public:
    ObjWrapper(const Obj* wrappee) {
        auto non_const_w = const_cast<Obj*>(wrappee);
        wrappee_ptr = {NewRef{}, non_const_w};
    }

private:
    IntrusivePtr<Obj> wrappee_ptr;
};



class ObjMgr {
public:
    void AddObj(const Obj* o) {
        if ( ! obj_collection.contains(o) )
            obj_collection.emplace(std::pair<const Obj*, ObjWrapper>{o, ObjWrapper(o)});
    }

private:
    std::unordered_map<const Obj*, ObjWrapper> obj_collection;
};

}
