

#pragma once

extern "C" {
#include "zeek/3rdparty/patricia.h"
}

#include <list>
#include <tuple>

#include "zeek/IPAddr.h"

namespace zeek {

class Val;
class SubNetVal;

namespace detail {

class PrefixTable {
private:
    struct iterator {
        patricia_node_t* Xstack[PATRICIA_MAXBITS + 1] = {};
        patricia_node_t** Xsp = nullptr;
        patricia_node_t* Xrn = nullptr;
        patricia_node_t* Xnode = nullptr;
    };

public:
    PrefixTable() {
        tree = New_Patricia(128);
        delete_function = nullptr;
    }
    ~PrefixTable() { Destroy_Patricia(tree, delete_function); }




    void* Insert(const IPAddr& addr, int width, void* data = nullptr);


    void* Insert(const Val* value, void* data = nullptr);




    void* Lookup(const IPAddr& addr, int width, bool exact = false) const;
    void* Lookup(const Val* value, bool exact = false) const;


    std::list<std::tuple<IPPrefix, void*>> FindAll(const IPAddr& addr, int width) const;
    std::list<std::tuple<IPPrefix, void*>> FindAll(const SubNetVal* value) const;


    void* Remove(const IPAddr& addr, int width);
    void* Remove(const Val* value);

    void Clear() { Clear_Patricia(tree, delete_function); }


    void SetDeleteFunction(data_fn_t del_fn) { delete_function = del_fn; }

    iterator InitIterator();
    void* GetNext(iterator* i);

private:
    static prefix_t* MakePrefix(const IPAddr& addr, int width);
    static IPPrefix PrefixToIPPrefix(prefix_t* p);

    patricia_tree_t* tree;
    data_fn_t delete_function;
};

}
}
