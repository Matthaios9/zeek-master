

#pragma once

#include "zeek/input/ReaderBackend.h"
#include "zeek/threading/formatters/Ascii.h"

namespace zeek::input::reader::detail {




class Benchmark : public ReaderBackend {
public:
    explicit Benchmark(ReaderFrontend* frontend);
    ~Benchmark() override;

    static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Benchmark(frontend); }

protected:
    bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields) override;
    void DoClose() override;
    bool DoUpdate() override;
    bool DoHeartbeat(double network_time, double current_time) override;

private:
    double CurrTime();
    std::string RandomString(const int len);
    threading::Value* EntryToVal(TypeTag Type, TypeTag subtype);

    int num_lines;
    double multiplication_factor;
    int spread;
    double autospread;
    int autospread_time;
    int add;
    int stopspreadat;
    double heartbeatstarttime;
    double timedspread;
    double heartbeat_interval;

    threading::formatter::Ascii* ascii;
};

}
