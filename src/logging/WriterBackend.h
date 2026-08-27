



#pragma once

#include <span>

#include "zeek/logging/Component.h"
#include "zeek/logging/Types.h"
#include "zeek/threading/MsgThread.h"

namespace broker {
class data;
}

namespace zeek::logging {

class WriterFrontend;










class WriterBackend : public threading::MsgThread {
public:












    explicit WriterBackend(WriterFrontend* frontend, bool send_heartbeats = true);




    ~WriterBackend() override;




    struct WriterInfo {

        using config_map = std::map<const char*, const char*, util::CompareString>;








        const char* path = nullptr;




        std::string filter_name;








        const char* post_proc_func = nullptr;




        double rotation_interval = 0.0;




        double rotation_base = 0.0;




        double network_time = 0.0;





        config_map config;

        WriterInfo() = default;

        WriterInfo(const WriterInfo& other) {
            path = other.path ? util::copy_string(other.path) : nullptr;
            post_proc_func = other.post_proc_func ? util::copy_string(other.post_proc_func) : nullptr;
            rotation_interval = other.rotation_interval;
            rotation_base = other.rotation_base;
            network_time = other.network_time;

            for ( const auto& [k, v] : other.config )
                config.insert(std::make_pair(util::copy_string(k), util::copy_string(v)));

            filter_name = other.filter_name;
        }

        ~WriterInfo() {
            delete[] path;
            delete[] post_proc_func;

            for ( auto [k, v] : config ) {
                delete[] k;
                delete[] v;
            }
        }



        broker::data ToBroker() const;
        bool FromBroker(broker::data d);

        const WriterInfo& operator=(const WriterInfo& other) = delete;
    };













    bool Init(int num_fields, const threading::Field* const* fields);











    bool Write(int arg_num_fields, std::span<detail::LogRecord> records);










    bool SetBuf(bool enabled);









    bool Flush(double network_time);







    bool Rotate(const char* rotated_path, double open, double close, bool terminating);







    void DisableFrontend();




    const WriterInfo& Info() const { return *info; }




    int NumFields() const { return num_fields; }




    const threading::Field* const* Fields() const { return fields; }






    bool IsBuf() { return buffering; }






















    bool FinishedRotation(const char* new_name, const char* old_name, double open, double close, bool terminating);











    bool FinishedRotation();


    bool OnHeartbeat(double network_time, double current_time) override;
    bool OnFinish(double network_time) override;



    using MsgThread::Info;

protected:
    friend class FinishMessage;




    void Heartbeat() override;










    virtual bool DoInit(const WriterInfo& info, int num_fields, const threading::Field* const* fields) = 0;











    virtual bool DoWrite(int num_fields, const threading::Field* const* fields, threading::Value** vals) = 0;



















    virtual bool DoSetBuf(bool enabled) = 0;















    virtual bool DoFlush(double network_time) = 0;



































    virtual bool DoRotate(const char* rotated_path, double open, double close, bool terminating) = 0;








    virtual bool DoFinish(double network_time) = 0;









    virtual bool DoHeartbeat(double network_time, double current_time) { return true; }

private:



    void DeleteVals(int num_writes, threading::Value*** vals);



    WriterFrontend* frontend;

    const WriterInfo* info;
    int num_fields;
    const threading::Field* const* fields;
    bool buffering;

    int rotation_counter;

    bool send_heartbeats;
};

}
