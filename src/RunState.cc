

#include "zeek/RunState.h"

#include "zeek/zeek-config.h"

#include <sys/types.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <ctime>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <ctime>
#endif
#endif

#include <csignal>
#include <cstdlib>

extern "C" {
#include "zeek/3rdparty/setsignal.h"
};

#include "zeek/Anon.h"
#include "zeek/Event.h"
#include "zeek/ID.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Timer.h"
#include "zeek/iosource/Manager.h"
#include "zeek/iosource/PktDumper.h"
#include "zeek/iosource/PktSrc.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/plugin/Manager.h"
#include "zeek/session/Manager.h"

static double last_watchdog_proc_time = 0.0;
extern int signal_val;

namespace zeek::run_state {
namespace detail {

iosource::PktDumper* pkt_dumper = nullptr;
iosource::PktSrc* current_pktsrc = nullptr;
iosource::IOSource* current_iosrc = nullptr;
bool have_pending_timers = false;
double first_wallclock = 0.0;
double first_timestamp = 0.0;
double current_wallclock = 0.0;
double current_pseudo = 0.0;
bool zeek_init_done = false;
bool time_updated = false;
bool bare_mode = false;

RETSIGTYPE watchdog(int ) {
    if ( processing_start_time != 0.0 ) {
















        if ( processing_start_time == last_watchdog_proc_time ) {





            double ct = util::current_time();

            int int_ct = static_cast<int>(ct);
            int frac_ct = static_cast<int>((ct - int_ct) * 1e6);

            int int_pst = static_cast<int>(processing_start_time);
            int frac_pst = static_cast<int>((processing_start_time - int_pst) * 1e6);

            if ( current_pkt ) {
                if ( ! pkt_dumper ) {




                    pkt_dumper = iosource_mgr->OpenPktDumper("watchdog-pkt.pcap", false);
                    if ( ! pkt_dumper || pkt_dumper->IsError() ) {
                        reporter->Error("watchdog: can't open watchdog-pkt.pcap for writing");
                        pkt_dumper = nullptr;
                    }
                }

                if ( pkt_dumper )
                    pkt_dumper->Dump(current_pkt);
            }

            get_final_stats();
            util::detail::set_processing_status("TERMINATING", "watchdog");

            reporter->FatalErrorWithCore("**watchdog timer expired, t = %d.%06d, start = %d.%06d, dispatched = %d",
                                         int_ct, frac_ct, int_pst, frac_pst, current_dispatched);
        }
    }

    last_watchdog_proc_time = processing_start_time;

    (void)alarm(zeek::detail::watchdog_interval);
    return RETSIGVAL;
}

void update_network_time(double new_network_time) {
    time_updated = true;
    network_time = new_network_time;
    PLUGIN_HOOK_VOID(HOOK_UPDATE_NETWORK_TIME, HookUpdateNetworkTime(new_network_time));
}


static bool should_forward_network_time() {


    if ( pseudo_realtime != 0.0 && run_state::detail::first_timestamp != 0.0 )
        return true;

    if ( iosource::PktSrc* ps = iosource_mgr->GetPktSrc() ) {


        if ( ! ps->IsLive() )
            return false;

        if ( ! ps->HasBeenIdleFor(BifConst::packet_source_inactivity_timeout) )
            return false;
    }



    return BifConst::allow_network_time_forward;
}

static void forward_network_time_if_applicable() {
    if ( ! should_forward_network_time() )
        return;

    double now = util::current_time(true);
    if ( now > network_time )
        update_network_time(now);

    return;
}

void init_run(const std::optional<std::string>& interface, const std::optional<std::string>& pcap_input_file,
              const std::optional<std::string>& pcap_output_file, bool do_watchdog) {
    if ( pcap_input_file ) {
        reading_live = pseudo_realtime > 0.0;
        reading_traces = true;

        iosource::PktSrc* ps = iosource_mgr->OpenPktSrc(*pcap_input_file, false);
        assert(ps);

        if ( ! ps->IsOpen() )
            reporter->FatalError("problem with trace file %s (%s)", pcap_input_file->c_str(), ps->ErrorMsg());
    }
    else if ( interface ) {
        reading_live = true;
        reading_traces = false;

        iosource::PktSrc* ps = iosource_mgr->OpenPktSrc(*interface, true);
        assert(ps);

        if ( ! ps->IsOpen() )
            reporter->FatalError("problem with interface %s (%s)", interface->c_str(), ps->ErrorMsg());
    }

    else




        reading_traces = reading_live = false;

    if ( pcap_output_file ) {
        const char* writefile = pcap_output_file->data();
        pkt_dumper = iosource_mgr->OpenPktDumper(writefile, false);
        assert(pkt_dumper);

        if ( ! pkt_dumper->IsOpen() )
            reporter->FatalError("problem opening dump file %s (%s)", writefile, pkt_dumper->ErrorMsg());

        if ( const auto& id = zeek::detail::global_scope()->Find("trace_output_file") )
            id->SetVal(make_intrusive<StringVal>(writefile));
        else
            reporter->Error("trace_output_file not defined");
    }

    zeek::detail::init_ip_addr_anonymizers();

    session_mgr = new session::Manager();

    if ( do_watchdog ) {

        (void)setsignal(SIGALRM, watchdog);
        (void)alarm(zeek::detail::watchdog_interval);
    }
}

void expire_timers() {
    current_dispatched +=
        zeek::detail::timer_mgr->Advance(network_time, zeek::detail::max_timer_expires - current_dispatched);
}

void dispatch_packet(Packet* pkt, iosource::PktSrc* pkt_src) {
    double t = pkt->time;

    if ( pseudo_realtime != 0.0 ) {
        current_wallclock = util::current_time(true);

        if ( first_wallclock == 0.0 ) {
            first_wallclock = util::current_time(true);
            first_timestamp = pkt->time;
        }


        t = check_pseudo_time(pkt);
    }

    if ( ! zeek_start_network_time ) {
        zeek_start_network_time = t;

        if ( network_time_init )
            event_mgr.Enqueue(network_time_init, Args{});
    }

    current_iosrc = pkt_src;
    current_pktsrc = pkt_src;


    update_network_time(zeek::detail::timer_mgr->Time() < t ? t : zeek::detail::timer_mgr->Time());
    processing_start_time = t;
    expire_timers();

    packet_mgr->ProcessPacket(pkt);
    event_mgr.Drain();

    processing_start_time = 0.0;
    current_dispatched = 0;

    current_iosrc = nullptr;
    current_pktsrc = nullptr;
}

void run_loop() {
    util::detail::set_processing_status("RUNNING", "run_loop");

    iosource::Manager::ReadySources ready;
    ready.reserve(iosource_mgr->TotalSize());

    while ( iosource_mgr->Size() || (BifConst::exit_only_after_terminate && ! terminating) ) {
        time_updated = false;
        iosource_mgr->FindReadySources(&ready);

#ifdef DEBUG
        static int loop_counter = 0;



        if ( ! ready.empty() || loop_counter++ % 100 == 0 ) {
            DBG_LOG(DBG_MAINLOOP, "realtime=%.6f ready_count=%zu", util::current_time(), ready.size());

            if ( ! ready.empty() )
                loop_counter = 0;
        }
#endif
        current_iosrc = nullptr;
        if ( ! ready.empty() ) {
            for ( const auto& src : ready ) {
                auto* iosrc = src.src;

                DBG_LOG(DBG_MAINLOOP, "processing source %s", iosrc->Tag());
                current_iosrc = iosrc;
                if ( iosrc->ImplementsProcessFd() && src.fd != -1 )
                    iosrc->ProcessFd(src.fd, src.flags);
                else
                    iosrc->Process();
            }
        }
        else if ( (have_pending_timers || BifConst::exit_only_after_terminate) && pseudo_realtime == 0.0 ) {









            forward_network_time_if_applicable();
            expire_timers();



            time_updated = true;
        }

        if ( ! time_updated )
            forward_network_time_if_applicable();

        event_mgr.Drain();

        processing_start_time = 0.0;
        current_dispatched = 0;
        current_iosrc = nullptr;

        if ( ::signal_val == SIGTERM || ::signal_val == SIGINT
#ifdef SIGBREAK
             || ::signal_val == SIGBREAK
#endif
        )



            zeek_terminate_loop("received termination signal");

        if ( ! reading_traces )


            have_pending_timers = zeek::detail::timer_mgr->Size() > 0;



        if ( pseudo_realtime != 0.0 ) {
            iosource::PktSrc* ps = iosource_mgr->GetPktSrc();
            if ( ps && ! ps->IsOpen() )
                iosource_mgr->Terminate();
        }
    }



    get_final_stats();
}

void get_final_stats() {
    iosource::PktSrc* ps = iosource_mgr->GetPktSrc();
    if ( ps && ps->IsLive() ) {
        iosource::PktSrc::Stats s;
        ps->Statistics(&s);

        auto pct = [](uint64_t v, uint64_t received) {
            return (static_cast<double>(v) / (static_cast<double>(v) + static_cast<double>(received))) * 100;
        };

        double dropped_pct = s.dropped > 0 ? pct(s.dropped, s.received) : 0.0;

        uint64_t unprocessed = packet_mgr->PacketsUnprocessed();
        double unprocessed_pct =
            unprocessed > 0 ? (static_cast<double>(unprocessed) / static_cast<double>(s.received)) * 100.0 : 0.0;

        std::string filtered = "";
        if ( s.filtered ) {
            double filtered_pct = s.filtered.value() > 0 ? pct(s.filtered.value(), s.received) : 0.0;
            filtered = zeek::util::fmt(" %" PRIu64 " (%.2f%%) filtered", s.filtered.value(), filtered_pct);
        }

        reporter->Info("%" PRIu64 " packets received on interface %s, %" PRIu64 " (%.2f%%) dropped, %" PRIu64
                       " (%.2f%%) not processed%s",
                       s.received, ps->Path().c_str(), s.dropped, dropped_pct, unprocessed, unprocessed_pct,
                       filtered.c_str());
    }
}

void delete_run() {
    util::detail::set_processing_status("TERMINATING", "delete_run");

    for ( auto& anon : zeek::detail::ip_anonymizer )
        delete anon;
}

double check_pseudo_time(const Packet* pkt) {
    assert(pkt->time > 0.0);
    assert(first_wallclock > 0.0);
    assert(first_timestamp > 0.0);
    double pseudo_time = pkt->time - first_timestamp;
    double ct = (util::current_time(true) - first_wallclock) * pseudo_realtime;

    current_pseudo = pseudo_time <= ct ? first_wallclock + pseudo_time : 0;

    DBG_LOG(DBG_MAINLOOP,
            "check_pseudo_time: first_wallclock=%.6f first_timestamp=%.6f pkt->time=%.6f pseudo_time=%.6f ct=%.6f "
            "current_pseudo=%.6f",
            first_wallclock, first_timestamp, pkt->time, pseudo_time, ct, current_pseudo);

    return current_pseudo;
}

iosource::PktSrc* current_packet_source() { return dynamic_cast<iosource::PktSrc*>(current_iosrc); }

}

double current_packet_timestamp() { return detail::current_pseudo; }

double current_packet_wallclock() {

    if ( run_state::is_processing_suspended() )
        detail::current_wallclock = util::current_time(true);

    return detail::current_wallclock;
}

bool reading_live = false;
bool reading_traces = false;
double pseudo_realtime = 0.0;
double network_time = 0.0;

double processing_start_time = 0.0;
double zeek_start_time = 0.0;
double zeek_start_network_time;
bool terminating = false;
bool is_parsing = false;

const Packet* current_pkt = nullptr;
int current_dispatched = 0;
double current_timestamp = 0.0;

static int _processing_suspended = 0;

void suspend_processing() {
    if ( _processing_suspended == 0 ) {
        DBG_LOG(DBG_MAINLOOP, "processing suspended");
        reporter->Info("processing suspended");
    }

    ++_processing_suspended;
}

void continue_processing() {
    if ( _processing_suspended == 1 ) {
        DBG_LOG(DBG_MAINLOOP, "processing continued");
        reporter->Info("processing continued");
        detail::current_wallclock = util::current_time(true);
    }

    if ( _processing_suspended > 0 )
        --_processing_suspended;
}

bool is_processing_suspended() { return _processing_suspended > 0; }

}
