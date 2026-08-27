

#include "zeek/iosource/pcap/Source.h"

#include "zeek/3rdparty/doctest.h"

#ifdef HAVE_PCAP_INT_H
#include <pcap-int.h>
#endif

#include <cstdio>

#include "zeek/Event.h"
#include "zeek/iosource/BPF_Program.h"
#include "zeek/iosource/Packet.h"
#include "zeek/iosource/pcap/pcap.bif.h"

namespace zeek::iosource::pcap {

PcapSource::~PcapSource() { Close(); }

PcapSource::PcapSource(const std::string& path, bool is_live) {
    props.path = path;
    props.is_live = is_live;
    pd = nullptr;
}

void PcapSource::Open() {
    if ( props.is_live )
        OpenLive();
    else
        OpenOffline();
}

void PcapSource::Close() {
    if ( ! pd )
        return;

    pcap_close(pd);
    pd = nullptr;

    Closed();

    if ( Pcap::file_done )
        event_mgr.Enqueue(Pcap::file_done, make_intrusive<StringVal>(props.path));
}

void PcapSource::OpenLive() {
    char errbuf[PCAP_ERRBUF_SIZE];


    if ( props.path.empty() ) {
        pcap_if_t* devs;

        if ( pcap_findalldevs(&devs, errbuf) < 0 ) {
            Error(util::fmt("pcap_findalldevs: %s", errbuf));
            return;
        }

        if ( devs ) {
            props.path = devs->name;
            pcap_freealldevs(devs);

            if ( props.path.empty() ) {
                Error("pcap_findalldevs: empty device name");
                return;
            }
        }
        else {
            Error("pcap_findalldevs: no devices found");
            return;
        }
    }


    uint32_t net;
    if ( pcap_lookupnet(props.path.c_str(), &net, &props.netmask, errbuf) < 0 ) {






        props.netmask = 0xffffff00;
    }

#ifdef PCAP_NETMASK_UNKNOWN

    if ( props.netmask == PCAP_NETMASK_UNKNOWN )
        props.netmask = PktSrc::NETMASK_UNKNOWN;
#endif

    pd = pcap_create(props.path.c_str(), errbuf);

    if ( ! pd ) {
        PcapError("pcap_create");
        return;
    }

    if ( pcap_set_snaplen(pd, BifConst::Pcap::snaplen) ) {
        PcapError("pcap_set_snaplen");
        return;
    }

    if ( pcap_set_promisc(pd, 1) ) {
        PcapError("pcap_set_promisc");
        return;
    }









    if ( pcap_set_timeout(pd, 1) ) {
        PcapError("pcap_set_timeout");
        return;
    }

    if ( pcap_set_buffer_size(pd, BifConst::Pcap::bufsize * 1024 * 1024) ) {
        PcapError("pcap_set_buffer_size");
        return;
    }

    if ( pcap_activate(pd) ) {
        PcapError("pcap_activate");
        return;
    }

#ifdef HAVE_LINUX
    if ( pcap_setnonblock(pd, 1, errbuf) < 0 ) {
        PcapError("pcap_setnonblock");
        return;
    }
#endif

#ifdef HAVE_PCAP_INT_H
    Info(util::fmt("pcap bufsize = %d\n", ((struct pcap*)pd)->bufsize));
#endif

#ifndef _MSC_VER
    props.selectable_fd = pcap_get_selectable_fd(pd);
#endif

    props.link_type = pcap_datalink(pd);
    props.is_live = true;

    Opened(props);
}

void PcapSource::OpenOffline() {
    char errbuf[PCAP_ERRBUF_SIZE];

    FILE* f = nullptr;
    if ( props.path == "-" ) {
        f = stdin;
    }
    else {
        if ( f = fopen(props.path.c_str(), "rb"); ! f ) {
            Error(util::fmt("unable to open %s: %s", props.path.c_str(), strerror(errno)));
            return;
        }



        if ( BifConst::Pcap::bufsize_offline_bytes != 0 ) {
            iobuf.resize(BifConst::Pcap::bufsize_offline_bytes);
            if ( util::detail::setvbuf(f, iobuf.data(), _IOFBF, iobuf.size()) != 0 ) {
                Error(util::fmt("unable to setvbuf %s: %s", props.path.c_str(), strerror(errno)));
                fclose(f);
                return;
            }
        }
    }



    pd = pcap_fopen_offline(f, errbuf);

    if ( ! pd ) {
        if ( f != stdin )
            fclose(f);

        Error(errbuf);
        return;
    }





    props.selectable_fd = -1;

    props.link_type = pcap_datalink(pd);
    props.is_live = false;

    Opened(props);
}

bool PcapSource::ExtractNextPacket(Packet* pkt) {
    if ( ! pd )
        return false;

    const u_char* data;
    pcap_pkthdr* header;

    int res = pcap_next_ex(pd, &header, &data);

    switch ( res ) {
        case PCAP_ERROR_BREAK:

            assert(! props.is_live);
            Close();
            return false;
        case PCAP_ERROR:

            if ( props.is_live )
                reporter->Error("failed to read a packet from %s: %s", props.path.data(), pcap_geterr(pd));
            else
                reporter->FatalError("failed to read a packet from %s: %s", props.path.data(), pcap_geterr(pd));
            return false;
        case 0:

            return false;
        case 1:




            if ( ! data ) {
                reporter->Weird("pcap_null_data_packet");
                return false;
            }
            break;
        default: reporter->InternalError("unhandled pcap_next_ex return value: %d", res); return false;
    }

    pkt->Init(props.link_type, &header->ts, header->caplen, header->len, data);

    if ( header->len == 0 || header->caplen == 0 ) {
        Weird("empty_pcap_header", pkt);
        return false;
    }

    ++stats.received;
    stats.bytes_received += header->len;






    header->len = 0;
    header->caplen = 0;

    return true;
}

void PcapSource::DoneWithPacket() {

}

detail::BPF_Program* PcapSource::CompileFilter(const std::string& filter) {
    auto code = std::make_unique<detail::BPF_Program>();

    if ( ! code->Compile(pd, filter.c_str(), Netmask()) ) {
        std::string msg = util::fmt("cannot compile BPF filter \"%s\"", filter.c_str());

        std::string state_msg = code->GetStateMessage();
        if ( ! state_msg.empty() )
            msg += ": " + state_msg;

        Error(msg);
    }

    return code.release();
}

bool PcapSource::SetFilter(int index) {
    if ( ! pd )
        return true;

    char errbuf[PCAP_ERRBUF_SIZE];

    iosource::detail::BPF_Program* code = GetBPFFilter(index);

    if ( ! code ) {
        snprintf(errbuf, sizeof(errbuf), "No precompiled pcap filter for index %d", index);
        Error(errbuf);
        return false;
    }

    if ( LinkType() == DLT_NFLOG ) {




    }
    else if ( auto program = code->GetProgram() ) {
        if ( pcap_setfilter(pd, program) < 0 ) {
            PcapError();
            return false;
        }
    }
    else if ( code->GetState() != FilterState::OK )
        return false;

#ifndef HAVE_LINUX

    stats.received = stats.dropped = stats.link = stats.bytes_received = 0;
#endif

    return true;
}



static void update_pktsrc_stats(PktSrc::Stats* stats, const struct pcap_stat* now, const struct pcap_stat* prev) {
    decltype(now->ps_drop) ps_drop_diff = 0;
    decltype(now->ps_recv) ps_recv_diff = 0;



    ps_recv_diff = now->ps_recv - prev->ps_recv;
    ps_drop_diff = now->ps_drop - prev->ps_drop;

    stats->link += ps_recv_diff;
    stats->dropped += ps_drop_diff;
}

void PcapSource::Statistics(Stats* s) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if ( ! (props.is_live && pd) )
        s->received = s->dropped = s->link = s->bytes_received = 0;

    else {
        struct pcap_stat pstat;
        if ( pcap_stats(pd, &pstat) < 0 ) {
            PcapError();
            s->received = s->dropped = s->link = s->bytes_received = 0;
        }

        else {
            update_pktsrc_stats(&stats, &pstat, &prev_pstat);
            prev_pstat = pstat;
        }
    }

    s->link = stats.link;
    s->dropped = stats.dropped;
    s->received = stats.received;
    s->bytes_received = stats.bytes_received;

    if ( ! props.is_live )
        s->dropped = 0;
}

void PcapSource::PcapError(const char* where) {
    std::string location;

    if ( where )
        location = util::fmt(" (%s)", where);

    if ( pd )
        Error(util::fmt("pcap_error: %s%s", pcap_geterr(pd), location.c_str()));
    else
        Error(util::fmt("pcap_error: not open%s", location.c_str()));

    Close();
}

iosource::PktSrc* PcapSource::Instantiate(const std::string& path, bool is_live) {
    return new PcapSource(path, is_live);
}

TEST_CASE("pcap source update_pktsrc_stats") {
    PktSrc::Stats stats;
    struct pcap_stat now = {0};
    struct pcap_stat prev = {0};

    SUBCASE("all zero") {
        update_pktsrc_stats(&stats, &now, &prev);
        CHECK(stats.link == 0);
        CHECK(stats.dropped == 0);
    }

    SUBCASE("no overflow") {
        now.ps_recv = 7;
        now.ps_drop = 3;
        update_pktsrc_stats(&stats, &now, &prev);
        CHECK(stats.link == 7);
        CHECK(stats.dropped == 3);
    }

    SUBCASE("no overflow prev") {
        stats.link = 2;
        stats.dropped = 1;
        prev.ps_recv = 2;
        prev.ps_drop = 1;
        now.ps_recv = 7;
        now.ps_drop = 3;

        update_pktsrc_stats(&stats, &now, &prev);
        CHECK(stats.link == 7);
        CHECK(stats.dropped == 3);
    }

    SUBCASE("overflow") {
        prev.ps_recv = 4294967295;
        prev.ps_drop = 4294967294;
        now.ps_recv = 0;
        now.ps_drop = 1;

        update_pktsrc_stats(&stats, &now, &prev);
        CHECK(stats.link == 1);
        CHECK(stats.dropped == 3);
    }

    SUBCASE("overflow 2") {
        stats.link = 4294967295;
        stats.dropped = 4294967294;
        prev.ps_recv = 4294967295;
        prev.ps_drop = 4294967294;
        now.ps_recv = 10;
        now.ps_drop = 3;

        update_pktsrc_stats(&stats, &now, &prev);
        CHECK(stats.link == 4294967306);
        CHECK(stats.dropped == 4294967299);
    }
}

}
