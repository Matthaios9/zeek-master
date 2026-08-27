

#pragma once

#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "zeek/plugin/Component.h"

namespace zeek::zeekygen::detail {

class Info;
class PackageInfo;
class ScriptInfo;
class IdentifierInfo;





struct TargetFile {







    explicit TargetFile(std::string arg_name);




    ~TargetFile();

    std::string name;
    FILE* f = nullptr;
};







class Target {
public:






    Target(std::string arg_name, std::string arg_pattern);




    virtual ~Target() = default;





    void FindDependencies(const std::vector<Info*>& infos) { DoFindDependencies(infos); }






    void Generate() const { DoGenerate(); }








    bool MatchesPattern(Info* info) const;




    std::string Name() const { return name; }




    std::string Pattern() const { return pattern; }

private:
    virtual void DoFindDependencies(const std::vector<Info*>& infos) = 0;

    virtual void DoGenerate() const = 0;

    std::string name;
    std::string pattern;
    std::string prefix;
};

template<class T>
static Target* create_target(const std::string& name, const std::string& pattern) {
    return new T(name, pattern);
}




class TargetFactory {
public:





    template<class T>
    void Register(const std::string& type_name) {
        target_creators[type_name] = &create_target<T>;
    }










    Target* Create(const std::string& type_name, const std::string& name, const std::string& pattern) {
        target_creator_map::const_iterator it = target_creators.find(type_name);

        if ( it == target_creators.end() )
            return nullptr;

        return it->second(name, pattern);
    }

private:
    using TargetFactoryFn = Target* (*)(const std::string& name, const std::string& pattern);
    using target_creator_map = std::map<std::string, TargetFactoryFn>;
    target_creator_map target_creators;
};




class AnalyzerTarget : public Target {
public:




    void CreateAnalyzerDoc(FILE* f) const { return DoCreateAnalyzerDoc(f); }

protected:
    using doc_creator_fn = void (*)(FILE*);

    AnalyzerTarget(const std::string& name, const std::string& pattern) : Target(name, pattern) {}

    void WriteAnalyzerElements(FILE* f, plugin::component::Type t, bool match_empty = false) const;

private:
    void DoFindDependencies(const std::vector<Info*>& infos) override;

    void DoGenerate() const override;

    virtual void DoCreateAnalyzerDoc(FILE* f) const = 0;
};




class ProtoAnalyzerTarget : public AnalyzerTarget {
public:





    ProtoAnalyzerTarget(const std::string& name, const std::string& pattern) : AnalyzerTarget(name, pattern) {}

private:
    void DoCreateAnalyzerDoc(FILE* f) const override;
};




class FileAnalyzerTarget : public AnalyzerTarget {
public:





    FileAnalyzerTarget(const std::string& name, const std::string& pattern) : AnalyzerTarget(name, pattern) {}

private:
    void DoCreateAnalyzerDoc(FILE* f) const override;
};




class PacketAnalyzerTarget : public AnalyzerTarget {
public:





    PacketAnalyzerTarget(const std::string& name, const std::string& pattern) : AnalyzerTarget(name, pattern) {}

private:
    void DoCreateAnalyzerDoc(FILE* f) const override;
};




class PackageTarget : public Target {
public:





    PackageTarget(const std::string& name, const std::string& pattern)
        : Target(name, pattern), pkg_deps(), script_deps(), pkg_manifest() {}

private:
    void DoFindDependencies(const std::vector<Info*>& infos) override;

    void DoGenerate() const override;

    std::vector<PackageInfo*> pkg_deps;
    std::vector<ScriptInfo*> script_deps;

    using manifest_t = std::map<PackageInfo*, std::vector<ScriptInfo*>>;
    manifest_t pkg_manifest;
};




class PackageIndexTarget : public Target {
public:





    PackageIndexTarget(const std::string& name, const std::string& pattern) : Target(name, pattern), pkg_deps() {}

private:
    void DoFindDependencies(const std::vector<Info*>& infos) override;

    void DoGenerate() const override;

    std::vector<PackageInfo*> pkg_deps;
};




class ScriptTarget : public Target {
public:








    ScriptTarget(const std::string& name, const std::string& pattern) : Target(name, pattern), script_deps() {}

    ~ScriptTarget() override {
        for ( auto* pkg : pkg_deps )
            delete pkg;
    }

protected:
    std::vector<ScriptInfo*> script_deps;

private:
    void DoFindDependencies(const std::vector<Info*>& infos) override;

    void DoGenerate() const override;

    bool IsDir() const { return Name()[Name().size() - 1] == '/'; }

    std::vector<Target*> pkg_deps;
};




class ScriptSummaryTarget : public ScriptTarget {
public:





    ScriptSummaryTarget(const std::string& name, const std::string& pattern) : ScriptTarget(name, pattern) {}

private:
    void DoGenerate() const override ;
};




class ScriptIndexTarget : public ScriptTarget {
public:





    ScriptIndexTarget(const std::string& name, const std::string& pattern) : ScriptTarget(name, pattern) {}

private:
    void DoGenerate() const override ;
};




class IdentifierTarget : public Target {
public:





    IdentifierTarget(const std::string& name, const std::string& pattern) : Target(name, pattern), id_deps() {}

private:
    void DoFindDependencies(const std::vector<Info*>& infos) override;

    void DoGenerate() const override;

    std::vector<IdentifierInfo*> id_deps;
};

}
