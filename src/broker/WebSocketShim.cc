

#include "zeek/broker/WebSocketShim.h"

#include <broker/hub.hh>
#include <memory>

#include "zeek/Reporter.h"
#include "zeek/broker/Manager.h"
#include "zeek/cluster/Backend.h"
#include "zeek/cluster/serializer/broker/Serializer.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/iosource/Manager.h"


#define BROKER_WS_DEBUG(...)                                                                                           \
    do {                                                                                                               \
        DBG_LOG(DBG_BROKER, __VA_ARGS__);                                                                              \
    } while ( 0 )

namespace zeek::Broker {

class WebSocketState {
public:
    WebSocketState() : hub(broker_mgr->MakeHub()) {}
    ~WebSocketState() {

        broker_mgr->DestroyHub(std::move(hub));
    }

    broker::hub hub;
};







class WebSocketShim::IOSource : public zeek::iosource::IOSource {
public:
    IOSource(WebSocketShim* shim) : shim(shim) {}

    void Close() {
        shim = nullptr;
        SetClosed(true);
    }


    void Process() override {
        if ( shim )
            shim->Process();
    }


    const char* Tag() override {
        if ( ! shim )
            return "<WebSocketShim orphan>";

        return shim->Name().c_str();
    }


    double GetNextTimeout() override { return -1; }

private:
    WebSocketShim* shim = nullptr;
};

WebSocketShim::WebSocketShim(std::unique_ptr<zeek::cluster::EventSerializer> es,
                             std::unique_ptr<zeek::cluster::LogSerializer> ls,
                             std::unique_ptr<zeek::cluster::detail::EventHandlingStrategy> ehs)
    : zeek::cluster::Backend("Broker_WebSocket_Shim", std::move(es), std::move(ls), std::move(ehs)) {
    iosrc = new IOSource(this);


    zeek::iosource_mgr->Register(iosrc, true );
}

WebSocketShim::~WebSocketShim() {
    try {
        DoTerminate();
    } catch ( ... ) {
        abort();
    }
}

bool WebSocketShim::DoInit() {
    state = std::make_unique<WebSocketState>();

    zeek::iosource_mgr->Register(iosrc, false);
    if ( ! zeek::iosource_mgr->RegisterFd(state->hub.read_fd(), iosrc) ) {
        zeek::reporter->Error("Failed to register hub.read_fd() with iosource_mgr");
        return false;
    }

    return true;
}

void WebSocketShim::DoTerminate() {
    if ( state ) {
        if ( iosrc ) {
            zeek::iosource_mgr->UnregisterFd(state->hub.read_fd(), iosrc);
            iosrc->Close();
            iosrc = nullptr;
        }
        else
            zeek::reporter->InternalWarning("Missing iosrc in WebSocketShim::DoTerminate()");

        state.reset();
    }
}

bool WebSocketShim::DoPublishEvent(const std::string& topic, cluster::Event& event) {
    auto r = cluster::detail::to_broker_event(event);
    if ( ! r ) {
        ProcessError("broker_error", "Failed to convert Zeek event to Broker event");
        return false;
    }

    size_t size = r->as_data().shared_envelope()->raw_bytes().second;
    Telemetry().OnOutgoingEvent(topic, r->name(), cluster::detail::SerializationInfo{size});

    auto msg = broker::data_envelope::make(broker::topic(topic), r->as_data());
    state->hub.publish(std::move(msg));
    return true;
}

bool WebSocketShim::DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) {
    BROKER_WS_DEBUG("DoSubscribe() topic %s", topic_prefix.c_str());



    state->hub.subscribe(topic_prefix, true);

    if ( cb )
        cb(topic_prefix, {zeek::cluster::Backend::CallbackStatus::Success});

    BROKER_WS_DEBUG("DoSubscribe '%s' done", topic_prefix.c_str());
    return true;
}

bool WebSocketShim::DoUnsubscribe(const std::string& topic_prefix) {
    state->hub.unsubscribe(topic_prefix, true);
    return true;
}

void WebSocketShim::Process() {
    if ( ! state )
        return;

    auto messages = state->hub.poll();

    BROKER_WS_DEBUG("Shim: Process() got %zu messages (%s)", messages.size(), NodeId().c_str());
    for ( auto& message : messages ) {
        auto&& topic = broker::get_topic(message);
        broker::zeek::visit_as_message([this, topic](auto& msg) { ProcessMessage(topic, msg); }, message);
    }
}

void WebSocketShim::ProcessMessage(std::string_view topic, broker::zeek::Batch& batch) {
    batch.for_each([this, topic](auto& inner) { ProcessMessage(topic, inner); });
}

void WebSocketShim::ProcessMessage(std::string_view topic, broker::zeek::Event& ev) {
    auto r = cluster::detail::to_zeek_event(ev);
    if ( ! r ) {
        std::string msg = zeek::util::fmt("Could not process remote event on topic '%s'", std::string(topic).c_str());
        ProcessError("broker_error", msg);
        return;
    }

    size_t size = ev.as_data().shared_envelope()->raw_bytes().second;
    Telemetry().OnIncomingEvent(topic, r->HandlerName(), cluster::detail::SerializationInfo{size});

    ProcessEvent(topic, std::move(*r));
}
void WebSocketShim::ProcessMessage(std::string_view topic, broker::zeek::Invalid& invalid) {
    zeek::reporter->Warning("ProcessMessage: Invalid on %s: %s", std::string(topic).c_str(),
                            invalid.to_string().c_str());
}

}






#include "broker/message.hh"
#include "broker/publisher.hh"

#include "zeek/3rdparty/doctest.h"

namespace {

TEST_SUITE_BEGIN("broker-websocket-shim");
using namespace std::literals;

TEST_CASE("tests") {

    broker::broker_options opts;
    opts.skip_ssl_init = true;
    opts.disable_forwarding = true;
    opts.disable_ssl = true;
    broker::configuration conf{opts};
    auto ep = broker::endpoint(std::move(conf));

    auto hub1 = ep.make_hub({"/abc"});
    auto hub2 = ep.make_hub({"/abc", "/cde"});
    auto sub1 = ep.make_subscriber({"/abc"});
    auto sub2 = ep.make_subscriber({"/abc", "/cde"});

    auto pub1 = ep.make_publisher(broker::topic{"/abc"});
    auto pub2 = ep.make_publisher(broker::topic{"/abc"});

    auto make_message = [](int value) { return broker::list_builder{}.add(value).build(); };

    auto make_data_message = [](auto topic, int value) {
        auto msg = broker::list_builder{}.add(value).build();
        return broker::make_data_message(broker::topic{topic}, msg);
    };

    constexpr auto expect_msg_timeout = 2ms;
    constexpr auto expect_no_msg_timeout = 5ms;

    SUBCASE("endpoint-publish") {

        auto dmsg = make_data_message("/abc", 1);
        ep.publish(dmsg->topic(), dmsg->value().to_data());

        auto h1msg = hub1.get(expect_msg_timeout);
        REQUIRE(h1msg != nullptr);
        CHECK_EQ("(1)", broker::to_string(h1msg->value()));

        auto h2msg = hub2.get(expect_msg_timeout);
        REQUIRE(h2msg != nullptr);
        CHECK_EQ("(1)", broker::to_string(h2msg->value()));

        auto s1msg = sub1.get(expect_no_msg_timeout);
        CHECK_FALSE(s1msg.has_value());
        auto s2msg = sub2.get(expect_no_msg_timeout);
        CHECK_FALSE(s2msg.has_value());
    }

    SUBCASE("publisher-publish") {

        auto dmsg = make_data_message("/abc", 2);
        pub1.publish(dmsg->value().to_data());

        auto h1msg = hub1.get(expect_msg_timeout);
        REQUIRE(h1msg != nullptr);
        CHECK_EQ("(2)", broker::to_string(h1msg->value()));

        auto h2msg = hub2.get(expect_msg_timeout);
        REQUIRE(h2msg != nullptr);
        CHECK_EQ("(2)", broker::to_string(h2msg->value()));

        auto s1msg = sub1.get(expect_no_msg_timeout);
        CHECK_FALSE(s1msg.has_value());

        auto s2msg = sub2.get(expect_no_msg_timeout);
        CHECK_FALSE(s2msg.has_value());
    }

    SUBCASE("hub-publish") {

        auto dmsg = make_data_message("/abc", 3);
        hub1.publish(dmsg);

        auto h1msg = hub1.get(expect_no_msg_timeout);
        CHECK_EQ(h1msg, nullptr);

        auto h2msg = hub2.get(expect_msg_timeout);
        REQUIRE(h2msg != nullptr);
        CHECK_EQ("(3)", broker::to_string(h2msg->value()));

        auto s1msg = sub1.get(expect_msg_timeout);
        REQUIRE(s1msg.has_value());
        CHECK_EQ("(3)", broker::to_string(s1msg.value()->value()));

        auto s2msg = sub2.get(expect_msg_timeout);
        REQUIRE(s2msg.has_value());
        CHECK_EQ("(3)", broker::to_string(s2msg.value()->value()));
    }

    SUBCASE("hub-publish-topic-cde") {

        auto dmsg = make_data_message("/cde", 3);
        hub1.publish(dmsg);

        auto h1msg = hub1.get(expect_no_msg_timeout);
        CHECK_EQ(h1msg, nullptr);

        auto h2msg = hub2.get(expect_msg_timeout);
        REQUIRE(h2msg != nullptr);
        CHECK_EQ("(3)", broker::to_string(h2msg->value()));


        auto s1msg = sub1.get(expect_no_msg_timeout);
        CHECK_FALSE(s1msg.has_value());

        auto s2msg = sub2.get(expect_msg_timeout);
        REQUIRE(s2msg.has_value());
        CHECK_EQ("(3)", broker::to_string(s2msg.value()->value()));
    }

    SUBCASE("hub-publish-recreated-hub-subscriber") {

        hub1 = ep.make_hub({"/efg"});
        sub1 = ep.make_subscriber({"/efg"});


        auto dmsg = make_data_message("/efg", 5);


        hub2.publish(dmsg);

        auto h1msg = hub1.get(expect_msg_timeout);
        REQUIRE(h1msg != nullptr);
        CHECK_EQ("(5)", broker::to_string(h1msg->value()));

        auto h2msg = hub2.get(expect_no_msg_timeout);
        CHECK_EQ(h2msg, nullptr);

        auto s1msg = sub1.get(expect_msg_timeout);
        REQUIRE(s1msg.has_value());
        CHECK_EQ("(5)", broker::to_string(s1msg.value()->value()));


        auto s2msg = sub2.get(expect_no_msg_timeout);
        CHECK_FALSE(s2msg.has_value());
    }






























































































}

TEST_SUITE_END();
}
