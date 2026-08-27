



#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>

#include "zeek/EventHandler.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/types.bif.netvar_h"

namespace zeek {

class Func;
class StringVal;
class RecordVal;
class TableVal;
class Val;
class VectorVal;

using FuncPtr = IntrusivePtr<Func>;
using RecordValPtr = IntrusivePtr<RecordVal>;
using StringValPtr = IntrusivePtr<StringVal>;
using ValPtr = IntrusivePtr<Val>;
using VectorValPtr = IntrusivePtr<VectorVal>;

namespace detail {

class Timer;




constexpr uint8_t table_change_to_bit(BifEnum::TableChange change) {
    assert(static_cast<int>(change) <= 7);
    return uint8_t{1} << static_cast<int>(change);
}















class PublishOnChangeState {
public:











    PublishOnChangeState(StringValPtr identifier, TableVal* tv, uint8_t change_mask, std::optional<std::string> topic,
                         FuncPtr topic_func, size_t max_batch_size, double max_batch_delay);




    virtual ~PublishOnChangeState();














    void OnChange(BifEnum::TableChange change, const Val& index, const ValPtr& value, const ValPtr& previous_value) {

        if ( in_apply_changes )
            return;

        if ( change_mask & table_change_to_bit(change) )
            QueueChange(change, index, value, previous_value);
    }



















    void QueueChange(BifEnum::TableChange change, const Val& index, const ValPtr& value, const ValPtr& previous_value);






    void PublishQueuedChanges(double now);













    void PublishQueuedChanges(double now, const std::string& topic, RecordValPtr tcheader, VectorValPtr tcinfos) const;







    void ApplyChanges(const RecordVal& tcheader, const VectorVal& tcinfos);




    void ResetTimer() { timer = nullptr; }






    void SetTopic(std::string t) { topic = std::move(t); }




    std::optional<std::string> GetTopic() const { return topic; }





    const FuncPtr& GetTopicFunc() const { return topic_func; }




    const StringValPtr& GetIdentifier() const { return identifier; }











    static std::unique_ptr<PublishOnChangeState> Instantiate(const std::string& id, TableVal* table_val,
                                                             const RecordVal& rec);









    static void SetTableChangeInfosForwardTopic(std::string topic) { forward_topic = std::move(topic); }




    static const StringValPtr& GetLocalNodeId();







    static void InitPostScript();

private:





    class InApplyChangesScope {
    public:
        InApplyChangesScope(PublishOnChangeState* arg_poc) : poc(arg_poc) { poc->in_apply_changes = true; }
        ~InApplyChangesScope() { poc->in_apply_changes = false; }

        PublishOnChangeState* poc = nullptr;
    };






    detail::Timer* ArmPublishTimer(double now);




    void CancelPublishTimer();

    StringValPtr identifier;
    TableVal* table_val = nullptr;
    uint8_t change_mask = 0;
    size_t max_batch_size = 0;
    double max_batch_delay = 0.0;
    bool in_apply_changes = false;




    std::optional<std::string> topic;
    VectorValPtr changes;





    FuncPtr topic_func;
    std::map<std::string, VectorValPtr, std::less<>> topic_changes;

    size_t queued_changes = 0;
    double last_publish_ts = 0.0;
    Timer* timer = nullptr;


    static EventHandlerPtr eh_table_change_infos;


    static EventHandlerPtr eh_forward_table_change_infos;

    static std::optional<std::string> forward_topic;

    static StringValPtr local_node_id;
};














bool cluster_publish_table(const std::string& topic, const zeek::TableVal& table_val, size_t batch_size);

}
}
