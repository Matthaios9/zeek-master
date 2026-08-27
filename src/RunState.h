

#pragma once

#include "zeek/zeek-config.h"

#include <optional>
#include <string>

namespace zeek {

class Packet;

namespace iosource {

class IOSource;
class PktSrc;
class PktDumper;

}

namespace run_state {
namespace detail {

extern void init_run(const std::optional<std::string>& interfaces, const std::optional<std::string>& pcap_input_file,
                     const std::optional<std::string>& pcap_output_file, bool do_watchdog);
extern void run_loop();
extern void get_final_stats();
extern void delete_run();
extern void update_network_time(double new_network_time);
extern void dispatch_packet(zeek::Packet* pkt, zeek::iosource::PktSrc* pkt_src);
extern void expire_timers();
extern void zeek_terminate_loop(const char* reason);





extern zeek::iosource::PktSrc* current_packet_source();

extern double check_pseudo_time(const Packet* pkt);

ZEEK_EXTERN_DATA zeek::iosource::IOSource* current_iosrc;
ZEEK_EXTERN_DATA zeek::iosource::PktDumper* pkt_dumper;






ZEEK_EXTERN_DATA bool have_pending_timers;

ZEEK_EXTERN_DATA double first_wallclock;


ZEEK_EXTERN_DATA double first_timestamp;
ZEEK_EXTERN_DATA double current_wallclock;
ZEEK_EXTERN_DATA double current_pseudo;

ZEEK_EXTERN_DATA bool zeek_init_done;

ZEEK_EXTERN_DATA bool bare_mode;

}



extern void suspend_processing();
extern void continue_processing();
bool is_processing_suspended();

extern double current_packet_wallclock();


ZEEK_EXTERN_DATA bool reading_live;




ZEEK_EXTERN_DATA bool reading_traces;




ZEEK_EXTERN_DATA double pseudo_realtime;



ZEEK_EXTERN_DATA double processing_start_time;


ZEEK_EXTERN_DATA double zeek_start_time;



ZEEK_EXTERN_DATA double zeek_start_network_time;


ZEEK_EXTERN_DATA double network_time;


ZEEK_EXTERN_DATA bool terminating;


ZEEK_EXTERN_DATA bool is_parsing;

ZEEK_EXTERN_DATA const zeek::Packet* current_pkt;
ZEEK_EXTERN_DATA int current_dispatched;
ZEEK_EXTERN_DATA double current_timestamp;

}
}
