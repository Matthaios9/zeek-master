

#pragma once

#include "zeek/input/Component.h"
#include "zeek/threading/MsgThread.h"

namespace zeek::detail {
class Location;
}

namespace zeek::input {

class ReaderFrontend;




enum ReaderMode : uint8_t {






    MODE_MANUAL,






    MODE_REREAD,






    MODE_STREAM,


    MODE_NONE
};










class ReaderBackend : public threading::MsgThread {
public:


    using threading::MsgThread::Error;
    using threading::MsgThread::Info;
    using threading::MsgThread::Warning;









    explicit ReaderBackend(ReaderFrontend* frontend);




    ~ReaderBackend() override;




    struct ReaderInfo {

        using config_map = std::map<const char*, const char*, util::CompareString>;








        const char* source;




        const char* name;





        config_map config;




        ReaderMode mode;

        ReaderInfo() {
            source = nullptr;
            name = nullptr;
            mode = MODE_NONE;
        }

        ReaderInfo(const ReaderInfo& other) {
            source = other.source ? util::copy_string(other.source) : nullptr;
            name = other.name ? util::copy_string(other.name) : nullptr;
            mode = other.mode;

            for ( const auto& [k, v] : other.config )
                config.insert(std::make_pair(util::copy_string(k), util::copy_string(v)));
        }

        ~ReaderInfo() {
            delete[] source;
            delete[] name;

            for ( auto [k, v] : config ) {
                delete[] k;
                delete[] v;
            }
        }

        const ReaderInfo& operator=(const ReaderInfo& other) = delete;
    };
















    bool Init(int num_fields, const threading::Field* const* fields);










    bool Update();





    void DisableFrontend();




    const threading::Field* const* Fields() const { return fields; }




    const ReaderInfo& Info() const { return *info; }




    int NumFields() const { return num_fields; }















    void FailWarn(bool is_error, const char* msg, bool suppress_future = false);

    void StopWarningSuppression();


    bool OnHeartbeat(double network_time, double current_time) override;
    bool OnFinish(double network_time) override;

    void Info(const char* msg) override;





    void Warning(const char* msg) override;










    void Error(const char* msg) override;

protected:




















    virtual bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields) = 0;












    virtual void DoClose() = 0;













    virtual bool DoUpdate() = 0;




    virtual bool DoHeartbeat(double network_time, double current_time) = 0;














    void Put(threading::Value** val);











    void Delete(threading::Value** val);







    void Clear();









    void EndOfData();













    void SendEntry(threading::Value** vals);









    void EndCurrentSend();

private:


    ReaderFrontend* frontend;

    ReaderInfo* info;
    unsigned int num_fields;
    const threading::Field* const* fields;

    bool disabled;


    bool suppress_warnings = false;
    size_t warnings_suppressed = 0;
};

}
