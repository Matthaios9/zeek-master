

#pragma once

#include <atomic>

#include "zeek/DebugLogger.h"
#include "zeek/threading/BasicThread.h"
#include "zeek/threading/Queue.h"

namespace zeek::detail {
class Location;
}

namespace zeek::threading {

struct Value;
struct Field;
class BasicInputMessage;
class BasicOutputMessage;

namespace detail {


class HeartbeatMessage;
class FinishMessage;
class FinishedMessage;
class KillMeMessage;
class IOSource;

}












class MsgThread : public BasicThread {
public:






    MsgThread();




    ~MsgThread() override;









    void SendIn(BasicInputMessage* msg) { return SendIn(msg, false); }








    void SendOut(BasicOutputMessage* msg) { return SendOut(msg, false); }











    void SendEvent(const char* name, const int num_vals, Value** vals);









    virtual void Info(const char* msg);















    virtual void Warning(const char* msg);















    virtual void Error(const char* msg);










    void FatalError(const char* msg);










    void FatalErrorWithCore(const char* msg);










    void InternalWarning(const char* msg);










    [[noreturn]] void InternalError(const char* msg);










    void Debug(DebugStream stream, const char* msg);




    struct Stats {
        uint64_t sent_in;
        uint64_t sent_out;
        uint64_t pending_in;
        uint64_t pending_out;



        Queue<BasicInputMessage*>::Stats queue_in_stats;
        Queue<BasicOutputMessage*>::Stats queue_out_stats;
    };







    void GetStats(Stats* stats);




    void Process();

protected:
    friend class Manager;
    friend class detail::HeartbeatMessage;
    friend class detail::FinishMessage;
    friend class detail::FinishedMessage;
    friend class detail::KillMeMessage;









    BasicOutputMessage* RetrieveOut();












    virtual void Heartbeat();





    bool Failed() const { return failed; }










    virtual bool OnHeartbeat(double network_time, double current_time) = 0;




    virtual bool OnFinish(double network_time) = 0;




    void Run() override;
    void OnWaitForStop() override;
    void OnSignalStop() override;
    void OnKill() override;










    virtual const zeek::detail::Location* GetLocationInfo() const { return nullptr; }

private:









    BasicInputMessage* RetrieveIn();












    void SendIn(BasicInputMessage* msg, bool force);












    void SendOut(BasicOutputMessage* msg, bool force);





    bool HasIn() { return queue_in.Ready(); }





    bool HasOut() { return queue_out.Ready(); }






    bool MightHaveOut() { return queue_out.MaybeReady(); }




    void Finished();

    std::string BuildMsgWithLocation(const char* msg);

    Queue<BasicInputMessage*> queue_in;
    Queue<BasicOutputMessage*> queue_out;

    std::atomic<uint64_t> cnt_sent_in;
    std::atomic<uint64_t> cnt_sent_out;

    bool main_finished;

    bool child_finished;
    bool child_sent_finish;
    bool failed;

    detail::IOSource* io_source = nullptr;
};




class Message {
public:



    virtual ~Message();






    const char* Name() const { return name; }




    virtual bool Process() = 0;

protected:






    explicit Message(const char* arg_name) { name = util::copy_string(arg_name); }

private:
    const char* name;
};




class BasicInputMessage : public Message {
protected:






    explicit BasicInputMessage(const char* name) : Message(name) {}
};




class BasicOutputMessage : public Message {
protected:






    explicit BasicOutputMessage(const char* name) : Message(name) {}
};





template<typename O>
class InputMessage : public BasicInputMessage {
public:



    O* Object() const { return object; }

protected:








    InputMessage(const char* name, O* arg_object) : BasicInputMessage(name) { object = arg_object; }

private:
    O* object;
};





template<typename O>
class OutputMessage : public BasicOutputMessage {
public:



    O* Object() const { return object; }

protected:








    OutputMessage(const char* name, O* arg_object) : BasicOutputMessage(name) { object = arg_object; }

private:
    O* object;
};

}
