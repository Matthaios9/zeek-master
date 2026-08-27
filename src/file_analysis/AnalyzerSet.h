

#pragma once

#include <memory>
#include <queue>

#include "zeek/Dict.h"
#include "zeek/Tag.h"

namespace zeek {

class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace file_analysis {

class Analyzer;
class File;

namespace detail {







class AnalyzerSet {
public:




    explicit AnalyzerSet(File* arg_file);





    ~AnalyzerSet();







    Analyzer* Find(const zeek::Tag& tag, RecordValPtr args);







    bool Add(const zeek::Tag& tag, RecordValPtr args);








    file_analysis::Analyzer* QueueAdd(const zeek::Tag& tag, RecordValPtr args);







    bool Remove(const zeek::Tag& tag, RecordValPtr args);







    bool QueueRemove(const zeek::Tag& tag, RecordValPtr args);




    void DrainModifications();


    using iterator = zeek::DictIterator<file_analysis::Analyzer>;
    using const_iterator = const iterator;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    iterator begin() { return analyzer_map.begin(); }
    iterator end() { return analyzer_map.end(); }
    const_iterator begin() const { return analyzer_map.begin(); }
    const_iterator end() const { return analyzer_map.end(); }
    const_iterator cbegin() { return analyzer_map.cbegin(); }
    const_iterator cend() { return analyzer_map.cend(); }

protected:






    std::unique_ptr<zeek::detail::HashKey> GetKey(const zeek::Tag& tag, RecordValPtr args) const;







    file_analysis::Analyzer* InstantiateAnalyzer(const zeek::Tag& tag, RecordValPtr args) const;






    void Insert(file_analysis::Analyzer* a, std::unique_ptr<zeek::detail::HashKey> key);







    bool Remove(const zeek::Tag& tag, std::unique_ptr<zeek::detail::HashKey> key);

private:
    File* file;
    PDict<file_analysis::Analyzer> analyzer_map;




    class Modification {
    public:
        virtual ~Modification() = default;






        virtual bool Perform(AnalyzerSet* set) = 0;




        virtual void Abort() = 0;
    };




    class AddMod final : public Modification {
    public:





        AddMod(file_analysis::Analyzer* arg_a, std::unique_ptr<zeek::detail::HashKey> arg_key)
            : Modification(), a(arg_a), key(std::move(arg_key)) {}
        bool Perform(AnalyzerSet* set) override;
        void Abort() override;

    protected:
        file_analysis::Analyzer* a;
        std::unique_ptr<zeek::detail::HashKey> key;
    };




    class RemoveMod final : public Modification {
    public:





        RemoveMod(zeek::Tag arg_tag, std::unique_ptr<zeek::detail::HashKey> arg_key)
            : Modification(), tag(std::move(arg_tag)), key(std::move(arg_key)) {}
        bool Perform(AnalyzerSet* set) override;
        void Abort() override {}

    protected:
        zeek::Tag tag;
        std::unique_ptr<zeek::detail::HashKey> key;
    };

    using ModQueue = std::queue<Modification*>;
    ModQueue mod_queue;
};

}
}
}
