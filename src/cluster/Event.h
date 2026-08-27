



#pragma once

#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/Val.h"
#include "zeek/ZeekArgs.h"

namespace zeek::cluster {




class Event {
public:



    Event(const EventHandlerPtr& handler, zeek::Args args, zeek::detail::EventMetadataVectorPtr meta)
        : handler(handler), args(std::move(args)), meta(std::move(meta)) {}




    std::string_view HandlerName() const { return handler->Name(); }




    const EventHandlerPtr& Handler() const { return handler; }




    const zeek::Args& Args() const { return args; }



    zeek::Args& Args() { return args; }




    double Timestamp() const;















    bool AddMetadata(const EnumValPtr& id, ValPtr val);




    const zeek::detail::EventMetadataVector* Metadata() const { return meta.get(); }




    std::tuple<zeek::EventHandlerPtr, zeek::Args, zeek::detail::EventMetadataVectorPtr> Take() &&;

private:
    EventHandlerPtr handler;
    zeek::Args args;
    zeek::detail::EventMetadataVectorPtr meta;
};


}
