

#include "zeek/threading/MsgThread.h"

#include <fcntl.h>
#include <unistd.h>
#include <csignal>

#include "zeek/DebugLogger.h"
#include "zeek/Desc.h"
#include "zeek/Obj.h"
#include "zeek/RunState.h"
#include "zeek/iosource/Manager.h"
#include "zeek/threading/Manager.h"


extern int signal_val;

namespace zeek::threading {
namespace detail {




class FinishMessage final : public InputMessage<MsgThread> {
public:
    FinishMessage(MsgThread* thread, double network_time)
        : InputMessage<MsgThread>("Finish", thread), network_time(network_time) {}

    bool Process() override {
        if ( Object()->child_finished )
            return true;
        bool result = Object()->OnFinish(network_time);
        Object()->Finished();
        return result;
    }

private:
    double network_time;
};


class FinishedMessage final : public OutputMessage<MsgThread> {
public:
    FinishedMessage(MsgThread* thread) : OutputMessage<MsgThread>("FinishedMessage", thread) {}

    bool Process() override {
        Object()->main_finished = true;
        return true;
    }
};


class HeartbeatMessage final : public InputMessage<MsgThread> {
public:
    HeartbeatMessage(MsgThread* thread, double arg_network_time, double arg_current_time)
        : InputMessage<MsgThread>("Heartbeat", thread) {
        network_time = arg_network_time;
        current_time = arg_current_time;
    }

    bool Process() override { return Object()->OnHeartbeat(network_time, current_time); }

private:
    double network_time;
    double current_time;
};


class ReporterMessage final : public OutputMessage<MsgThread> {
public:
    enum Type : uint8_t { INFO, WARNING, ERROR, FATAL_ERROR, FATAL_ERROR_WITH_CORE, INTERNAL_WARNING, INTERNAL_ERROR };

    ReporterMessage(Type arg_type, MsgThread* thread, std::string_view arg_msg)
        : OutputMessage<MsgThread>("ReporterMessage", thread) {
        type = arg_type;
        msg = util::copy_string(arg_msg.data(), arg_msg.size());
    }

    ~ReporterMessage() override { delete[] msg; }

    bool Process() override;

private:
    const char* msg;
    Type type;
};


class KillMeMessage final : public OutputMessage<MsgThread> {
public:
    KillMeMessage(MsgThread* thread) : OutputMessage<MsgThread>("ReporterMessage", thread) {}

    bool Process() override {
        Object()->SignalStop();
        Object()->WaitForStop();
        thread_mgr->KillThread(Object());
        return true;
    }
};


class DebugMessage final : public OutputMessage<MsgThread> {
public:
    DebugMessage(DebugStream arg_stream, MsgThread* thread, std::string_view arg_msg)
        : OutputMessage<MsgThread>("DebugMessage", thread) {
        stream = arg_stream;
        msg = util::copy_string(arg_msg.data(), arg_msg.size());
    }

    ~DebugMessage() override { delete[] msg; }

    bool Process() override {
        zeek::detail::debug_logger.Log(stream, "%s: %s", Object()->Name(), msg);
        return true;
    }

private:
    const char* msg;
    DebugStream stream;
};


class SendEventMessage final : public OutputMessage<MsgThread> {
public:
    SendEventMessage(MsgThread* thread, const char* name, const int num_vals, Value** val)
        : OutputMessage<MsgThread>("SendEvent", thread), name(util::copy_string(name)), num_vals(num_vals), val(val) {}

    ~SendEventMessage() override { delete[] name; }

    bool Process() override {
        bool success = thread_mgr->SendEvent(Object(), name, num_vals, val);

        if ( ! success )
            reporter->Error("SendEvent for event %s failed", name);

        return true;
    }

private:
    const char* name;
    const int num_vals;
    Value** val;
};

bool ReporterMessage::Process() {
    switch ( type ) {
        case INFO: reporter->Info("%s: %s", Object()->Name(), msg); break;

        case WARNING: reporter->Warning("%s: %s", Object()->Name(), msg); break;

        case ERROR: reporter->Error("%s: %s", Object()->Name(), msg); break;

        case FATAL_ERROR: reporter->FatalError("%s: %s", Object()->Name(), msg); break;

        case FATAL_ERROR_WITH_CORE: reporter->FatalErrorWithCore("%s: %s", Object()->Name(), msg); break;

        case INTERNAL_WARNING: reporter->InternalWarning("%s: %s", Object()->Name(), msg); break;

        case INTERNAL_ERROR: reporter->InternalError("%s: %s", Object()->Name(), msg); break;

        default: reporter->InternalError("unknown ReporterMessage type %d", type);
    }

    return true;
}







class IOSource : public iosource::IOSource {
public:
    explicit IOSource(MsgThread* thread) : thread(thread) {
        if ( ! iosource_mgr->RegisterFd(flare.FD(), this) )
            reporter->InternalError("Failed to register MsgThread FD with iosource_mgr");

        SetClosed(false);
    }

    ~IOSource() override {
        if ( ! iosource_mgr->UnregisterFd(flare.FD(), this) )
            reporter->InternalError("Failed to unregister MsgThread FD from iosource_mgr");
    }

    void Process() override {
        flare.Extinguish();

        if ( thread )
            thread->Process();
    }

    const char* Tag() override { return thread ? thread->Name() : "<MsgThread orphan>"; }

    double GetNextTimeout() override { return -1; }


    void Fire() { flare.Fire(); };

    void Close() {
        thread = nullptr;
        SetClosed(true);
    }

private:
    MsgThread* thread = nullptr;
    zeek::detail::Flare flare;
};

}



Message::~Message() { delete[] name; }

MsgThread::MsgThread() : BasicThread(), queue_in(this, nullptr), queue_out(nullptr, this) {
    cnt_sent_in.store(0);
    cnt_sent_out.store(0);

    main_finished = false;
    child_finished = false;
    child_sent_finish = false;
    failed = false;
    thread_mgr->AddMsgThread(this);

    io_source = new detail::IOSource(this);


    iosource_mgr->Register(io_source, true);
}

MsgThread::~MsgThread() {



    if ( io_source ) {
        io_source->Close();
        io_source = nullptr;
    }
}

void MsgThread::OnSignalStop() {
    if ( main_finished || Killed() || child_sent_finish )
        return;

    child_sent_finish = true;

    SendIn(new detail::FinishMessage(this, run_state::network_time), true);
}

void MsgThread::OnWaitForStop() {
    int signal_count = 0;
    int old_signal_val = signal_val;
    signal_val = 0;

    int cnt = 0;
    uint64_t last_size = 0;
    uint64_t cur_size = 0;

    while ( ! main_finished ) {

        if ( signal_val == SIGTERM || signal_val == SIGINT ) {
            ++signal_count;

            if ( signal_count == 1 ) {


                fprintf(stderr, "received signal while waiting for thread %s, aborting all ...\n", Name());
                thread_mgr->KillThreads();
            }
            else {


                fprintf(stderr, "received another signal while waiting for thread %s, aborting processing\n", Name());
                exit(1);
            }

            signal_val = 0;
        }

        if ( ! Killed() )
            queue_in.WakeUp();

        while ( HasOut() ) {
            Message* msg = RetrieveOut();
            assert(msg);

            if ( ! msg->Process() )
                reporter->Error("%s failed during thread termination", msg->Name());

            delete msg;
        }

        if ( ! Killed() )
            usleep(1000);
    }

    signal_val = old_signal_val;
}

void MsgThread::OnKill() {



    if ( io_source ) {
        io_source->Close();
        io_source = nullptr;
    }




    queue_in.WakeUp();
}

void MsgThread::Heartbeat() {
    if ( child_sent_finish )
        return;

    SendIn(new detail::HeartbeatMessage(this, run_state::network_time, util::current_time()));
}

void MsgThread::Finished() {
    child_finished = true;
    SendOut(new detail::FinishedMessage(this));
}

std::string MsgThread::BuildMsgWithLocation(const char* msg) {
    ODesc desc;

    if ( auto* location = GetLocationInfo() ) {
        location->Describe(&desc);
        desc.Add(": ");
    }

    desc.Add(msg);
    return desc.Description();
}

void MsgThread::Info(const char* msg) {
    SendOut(new detail::ReporterMessage(detail::ReporterMessage::INFO, this, BuildMsgWithLocation(msg)));
}

void MsgThread::Warning(const char* msg) {
    SendOut(new detail::ReporterMessage(detail::ReporterMessage::WARNING, this, BuildMsgWithLocation(msg)));
}

void MsgThread::Error(const char* msg) {
    SendOut(new detail::ReporterMessage(detail::ReporterMessage::ERROR, this, BuildMsgWithLocation(msg)));
}

void MsgThread::FatalError(const char* msg) {
    SendOut(new detail::ReporterMessage(detail::ReporterMessage::FATAL_ERROR, this, BuildMsgWithLocation(msg)));
}

void MsgThread::FatalErrorWithCore(const char* msg) {
    SendOut(
        new detail::ReporterMessage(detail::ReporterMessage::FATAL_ERROR_WITH_CORE, this, BuildMsgWithLocation(msg)));
}

void MsgThread::InternalWarning(const char* msg) {
    SendOut(new detail::ReporterMessage(detail::ReporterMessage::INTERNAL_WARNING, this, BuildMsgWithLocation(msg)));
}

void MsgThread::InternalError(const char* msg) {
    fprintf(stderr, "internal error in thread: %s\n", BuildMsgWithLocation(msg).c_str());
    abort();
}

void MsgThread::Debug(DebugStream stream, const char* msg) {
    SendOut(new detail::DebugMessage(stream, this, BuildMsgWithLocation(msg)));
}

void MsgThread::SendIn(BasicInputMessage* msg, bool force) {
    if ( Terminating() && ! force ) {
        delete msg;
        return;
    }

    DBG_LOG(DBG_THREADING, "Sending '%s' to %s ...", msg->Name(), Name());

    queue_in.Put(msg);
    ++cnt_sent_in;

    zeek::thread_mgr->MessageIn();
}

void MsgThread::SendOut(BasicOutputMessage* msg, bool force) {
    if ( Terminating() && ! force ) {
        delete msg;
        return;
    }

    queue_out.Put(msg);

    ++cnt_sent_out;

    zeek::thread_mgr->MessageOut();

    if ( io_source )
        io_source->Fire();
}

void MsgThread::SendEvent(const char* name, const int num_vals, Value** vals) {
    SendOut(new detail::SendEventMessage(this, name, num_vals, vals));
}

BasicOutputMessage* MsgThread::RetrieveOut() {
    BasicOutputMessage* msg = queue_out.Get();
    if ( ! msg )
        return nullptr;

    DBG_LOG(DBG_THREADING, "Retrieved '%s' from %s", msg->Name(), Name());

    return msg;
}

BasicInputMessage* MsgThread::RetrieveIn() {
    BasicInputMessage* msg = queue_in.Get();

    if ( ! msg )
        return nullptr;

#ifdef DEBUG
    std::string s = Fmt("Retrieved '%s' in %s", msg->Name(), Name());
    Debug(DBG_THREADING, s.c_str());
#endif

    return msg;
}

void MsgThread::Run() {
    while ( ! (child_finished || Killed()) ) {
        BasicInputMessage* msg = RetrieveIn();

        if ( ! msg )
            continue;

        bool result = msg->Process();

        delete msg;

        if ( ! result ) {
            Error("terminating thread");





            SendOut(new detail::KillMeMessage(this));
            failed = true;
        }
    }




    if ( ! child_finished && ! Killed() ) {
        OnFinish(run_state::network_time);
        Finished();
    }
}

void MsgThread::GetStats(Stats* stats) {
    stats->sent_in = cnt_sent_in.load();
    stats->sent_out = cnt_sent_out.load();
    stats->pending_in = queue_in.Size();
    stats->pending_out = queue_out.Size();
    queue_in.GetStats(&stats->queue_in_stats);
    queue_out.GetStats(&stats->queue_out_stats);
}

void MsgThread::Process() {
    while ( HasOut() ) {
        Message* msg = RetrieveOut();
        assert(msg);

        if ( ! msg->Process() ) {
            reporter->Error("%s failed, terminating thread", msg->Name());
            SignalStop();
        }

        delete msg;
    }
}

}
