












#pragma once

#include "zeek/script_opt/CPP/InitsInfo.h"

namespace zeek::detail {



template<class T>
class CPPTracker {
public:



    CPPTracker(const char* _base_name, bool _single_global) : base_name(_base_name), single_global(_single_global) {}


    bool HasKey(const T* key) const { return map.count(key) > 0; }
    bool HasKey(IntrusivePtr<T> key) const { return HasKey(key.get()); }


    void AddKey(IntrusivePtr<T> key, p_hash_type h);

    void AddInitInfo(const T* rep, std::shared_ptr<CPP_InitInfo> gi) { gi_s[rep] = std::move(gi); }


    std::string KeyName(const T* key);
    std::string KeyName(IntrusivePtr<T> key) { return KeyName(key.get()); }



    const std::vector<IntrusivePtr<T>>& DistinctKeys() const { return keys; }


    const T* GetRep(const T* key) {
        ASSERT(HasKey(key));
        return reps[map[key]];
    }
    const T* GetRep(IntrusivePtr<T> key) { return GetRep(key.get()); }

private:

    std::unordered_map<const T*, p_hash_type> map;

    std::unordered_map<const T*, std::shared_ptr<CPP_InitInfo>> gi_s;


    std::unordered_map<p_hash_type, int> map2;



    std::vector<IntrusivePtr<T>> keys;


    std::unordered_map<p_hash_type, const T*> reps;


    std::string base_name;



    bool single_global;
};

}
