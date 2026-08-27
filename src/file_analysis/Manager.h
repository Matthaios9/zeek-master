

#pragma once

#include "zeek/zeek-config.h"

#include <map>
#include <set>
#include <string>

#include "zeek/RuleMatcher.h"
#include "zeek/Tag.h"
#include "zeek/file_analysis/Component.h"
#include "zeek/file_analysis/FileTimer.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek {

class TableVal;
class VectorVal;

namespace run_state {

extern bool terminating;

}

namespace analyzer {

class Analyzer;

}

namespace detail {
class CompositeHash;
}

namespace file_analysis {

class File;




class Manager : public plugin::ComponentManager<Component> {
public:



    Manager();




    ~Manager();





    void InitPreScript();





    void InitPostScript();





    void InitMagic();




    void Terminate();







    std::string HashHandle(const std::string& handle) const;







    void SetHandle(const std::string& handle);

























    std::string DataIn(const u_char* data, uint64_t len, uint64_t offset, const zeek::Tag& tag, Connection* conn,
                       bool is_orig, const std::string& precomputed_file_id = "", const std::string& mime_type = "");























    std::string DataIn(const u_char* data, uint64_t len, const zeek::Tag& tag, Connection* conn, bool is_orig,
                       const std::string& precomputed_file_id = "", const std::string& mime_type = "");
















    void DataIn(const u_char* data, uint64_t len, const std::string& file_id, const std::string& source,
                const std::string& mime_type = "");

















    void DataIn(const u_char* data, uint64_t len, uint64_t offset, const std::string& file_id,
                const std::string& source, const std::string& mime_type = "");







    void EndOfFile(const zeek::Tag& tag, Connection* conn);







    void EndOfFile(const zeek::Tag& tag, Connection* conn, bool is_orig);





    void EndOfFile(const std::string& file_id);

















    std::string Gap(uint64_t offset, uint64_t len, const zeek::Tag& tag, Connection* conn, bool is_orig,
                    const std::string& precomputed_file_id = "");
















    std::string SetSize(uint64_t size, const zeek::Tag& tag, Connection* conn, bool is_orig,
                        const std::string& precomputed_file_id = "");







    bool IgnoreFile(const std::string& file_id);









    bool SetTimeoutInterval(const std::string& file_id, double interval) const;




    bool EnableReassembly(const std::string& file_id);




    bool DisableReassembly(const std::string& file_id);




    bool SetReassemblyBuffer(const std::string& file_id, uint64_t max);











    bool SetExtractionLimit(const std::string& file_id, RecordValPtr args, uint64_t n) const;







    File* LookupFile(const std::string& file_id) const;










    bool AddAnalyzer(const std::string& file_id, const zeek::Tag& tag, RecordValPtr args) const;








    bool RemoveAnalyzer(const std::string& file_id, const zeek::Tag& tag, RecordValPtr args) const;






    bool IsIgnored(const std::string& file_id);








    Analyzer* InstantiateAnalyzer(const Tag& tag, RecordValPtr args, File* f) const;












    zeek::detail::RuleMatcher::MIME_Matches* DetectMIME(const u_char* data, uint64_t len,
                                                        zeek::detail::RuleMatcher::MIME_Matches* rval) const;








    std::string DetectMIME(const u_char* data, uint64_t len) const;












    std::string GetFileID(const zeek::Tag& tag, Connection* c, bool is_orig);

    uint64_t CurrentFiles() { return id_map.size(); }

    uint64_t MaxFiles() { return max_files; }

    uint64_t CumulativeFiles() { return cumulative_files; }

    zeek::detail::CompositeHash* GetAnalyzerHash() const { return analyzer_hash; }

protected:
    friend class detail::FileTimer;



















    File* GetFile(const std::string& file_id, Connection* conn = nullptr, const zeek::Tag& tag = zeek::Tag::Error,
                  bool is_orig = false, bool update_conn = true, const char* source_name = nullptr);








    void Timeout(const std::string& file_id, bool is_terminating = run_state::terminating);






    bool RemoveFile(const std::string& file_id);









    static bool IsDisabled(const zeek::Tag& tag);

private:
    using TagSet = std::set<Tag>;
    using MIMEMap = std::map<std::string, TagSet*>;

    TagSet* LookupMIMEType(const std::string& mtype, bool add_if_not_found);

    std::map<std::string, File*> id_map;
    std::set<std::string> ignored;
    std::string current_file_id;
    zeek::detail::RuleFileMagicState* magic_state = nullptr;
    MIMEMap mime_types;

    inline static TableVal* disabled = nullptr;
    inline static TableType* tag_set_type = nullptr;

    size_t cumulative_files = 0;
    size_t max_files = 0;

    zeek::detail::CompositeHash* analyzer_hash = nullptr;
};





VectorValPtr GenMIMEMatchesVal(const zeek::detail::RuleMatcher::MIME_Matches& m);

}

ZEEK_EXTERN_DATA file_analysis::Manager* file_mgr;

}
