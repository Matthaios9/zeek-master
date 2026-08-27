

#pragma once

#include <ctime>
#include <list>
#include <map>
#include <string>
#include <vector>

#include "zeek/ID.h"
#include "zeek/zeekygen/Info.h"

namespace zeek {

class TypeDecl;

namespace zeekygen::detail {

class ScriptInfo;




class IdentifierInfo : public Info {
public:








    IdentifierInfo(zeek::detail::IDPtr id, ScriptInfo* script, bool from_redef = false);




    ~IdentifierInfo() override;




    const ValPtr& InitialVal() const { return initial_val; }







    void AddComment(const std::string& comment) {
        last_field_seen ? last_field_seen->comments.push_back(comment) : comments.push_back(comment);
    }






    void AddComments(const std::vector<std::string>& cmtns) {
        comments.insert(comments.end(), cmtns.begin(), cmtns.end());
    }








    void AddRedef(const std::string& from_script, zeek::detail::InitClass ic, zeek::detail::ExprPtr init_expr,
                  std::vector<std::string> comments);










    void AddRecordField(const TypeDecl* field, const std::string& script, std::vector<std::string>& comments,
                        bool from_redef);






    void CompletedTypeDecl() { last_field_seen = nullptr; }




    zeek::detail::ID* GetID() const { return id.get(); }




    ScriptInfo* GetDeclaringScript() const { return declaring_script; }





    std::string GetDeclaringScriptForField(const std::string& field) const;





    bool IsFromRedef() const { return from_redef; }





    bool FieldIsFromRedef(const std::string& field) const;




    std::vector<std::string> GetComments() const;





    std::vector<std::string> GetFieldComments(const std::string& field) const;




    struct Redefinition {
        std::string from_script;
        zeek::detail::InitClass ic;
        zeek::detail::ExprPtr init_expr;
        std::vector<std::string> comments;
        bool omit_value = false;

        Redefinition(std::string arg_script, zeek::detail::InitClass arg_ic, zeek::detail::ExprPtr arg_expr,
                     std::vector<std::string> arg_comments, bool arg_omit_value);

        ~Redefinition();
    };







    std::list<Redefinition> GetRedefs(const std::string& from_script) const;





    const std::list<Redefinition*>& GetRedefs() const { return redefs; }

private:
    time_t DoGetModificationTime() const override;

    std::string DoName() const override { return id->Name(); }

    std::string DoReStructuredText(bool roles_only) const override;

    struct RecordField {
        ~RecordField();

        TypeDecl* field;
        std::string from_script;
        std::vector<std::string> comments;
        bool from_redef;
    };

    using redef_list = std::list<Redefinition*>;
    using record_field_map = std::map<std::string, RecordField*>;

    std::vector<std::string> comments;
    zeek::detail::IDPtr id;
    ValPtr initial_val;
    redef_list redefs;
    record_field_map fields;
    RecordField* last_field_seen = nullptr;
    ScriptInfo* declaring_script = nullptr;
    bool from_redef = false;
};

}
}
