

#include "zeek/Frag.h"

#include "zeek/IP.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/session/Manager.h"

constexpr uint32_t MIN_ACCEPTABLE_FRAG_SIZE = 64;
constexpr uint32_t MAX_ACCEPTABLE_FRAG_SIZE = 64000;

namespace zeek::detail {

FragTimer::~FragTimer() {
    if ( f )
        f->ClearTimer();
}

void FragTimer::Dispatch(double t, bool ) {
    if ( f )
        f->Expire(t);
    else
        reporter->InternalWarning("fragment timer dispatched w/o reassembler");
}

FragReassembler::FragReassembler(session::Manager* arg_s, const std::shared_ptr<IP_Hdr>& ip, const u_char* pkt,
                                 const FragReassemblerKey& k, double t)
    : Reassembler(0, REASSEM_FRAG) {
    s = arg_s;
    key = k;

    const struct ip* ip4 = ip->IP4_Hdr();
    if ( ip4 ) {
        proto_hdr_len = ip->HdrLen();
        proto_hdr = new u_char[64];

        memcpy(proto_hdr, ip4, proto_hdr_len);
    }
    else {
        proto_hdr_len = ip->HdrLen() - 8;
        proto_hdr = new u_char[proto_hdr_len];
        memcpy(proto_hdr, ip->IP6_Hdr(), proto_hdr_len);
    }

    reassembled_pkt = nullptr;
    frag_size = 0;
    next_proto = ip->NextProto();

    if ( frag_timeout != 0.0 ) {
        expire_timer = new FragTimer(this, t + frag_timeout);
        timer_mgr->Add(expire_timer);
    }
    else
        expire_timer = nullptr;

    AddFragment(t, ip, pkt);
}

FragReassembler::~FragReassembler() {
    DeleteTimer();
    delete[] proto_hdr;
}

void FragReassembler::AddFragment(double t, const std::shared_ptr<IP_Hdr>& ip, const u_char* pkt) {
    const struct ip* ip4 = ip->IP4_Hdr();

    if ( ip4 ) {
        if ( ip4->ip_p != (reinterpret_cast<const struct ip*>(proto_hdr))->ip_p ||
             ip4->ip_hl != (reinterpret_cast<const struct ip*>(proto_hdr))->ip_hl )




            s->Weird("fragment_protocol_inconsistency", ip.get());
    }
    else {
        if ( ip->NextProto() != next_proto || ip->HdrLen() - 8 != proto_hdr_len )
            s->Weird("fragment_protocol_inconsistency", ip.get());

    }

    if ( ip->DF() )

        s->Weird("fragment_with_DF", ip.get());

    uint16_t offset = ip->FragOffset();
    uint32_t len = ip->TotalLen();
    uint16_t hdr_len = ip->HdrLen();

    if ( len < hdr_len ) {
        s->Weird("fragment_protocol_inconsistency", ip.get());
        return;
    }

    uint64_t upper_seq = offset + len - hdr_len;

    if ( ! offset )

        next_proto = ip->NextProto();

    if ( ! ip->MF() ) {

        if ( frag_size == 0 )
            frag_size = upper_seq;

        else if ( upper_seq != frag_size ) {
            s->Weird("fragment_size_inconsistency", ip.get());

            if ( upper_seq > frag_size )
                frag_size = upper_seq;
        }
    }

    else if ( len < MIN_ACCEPTABLE_FRAG_SIZE )
        s->Weird("excessively_small_fragment", ip.get());

    if ( upper_seq > MAX_ACCEPTABLE_FRAG_SIZE )
        s->Weird("excessively_large_fragment", ip.get());

    if ( frag_size && upper_seq > frag_size ) {





        s->Weird("fragment_size_inconsistency", ip.get());
        frag_size = upper_seq;
    }





    pkt += hdr_len;
    len -= hdr_len;

    NewBlock(run_state::network_time, offset, len, pkt);
}

void FragReassembler::Weird(const char* name) const {
    unsigned int version = (reinterpret_cast<const ip*>(proto_hdr))->ip_v;

    if ( version == 4 ) {
        IP_Hdr hdr(reinterpret_cast<const ip*>(proto_hdr), false);
        s->Weird(name, &hdr);
    }

    else if ( version == 6 ) {
        IP_Hdr hdr(reinterpret_cast<const ip6_hdr*>(proto_hdr), false, proto_hdr_len);
        s->Weird(name, &hdr);
    }

    else {
        reporter->InternalWarning("Unexpected IP version in FragReassembler");
        reporter->Weird(name);
    }
}

void FragReassembler::Overlap(const u_char* b1, const u_char* b2, uint64_t n) {
    if ( memcmp(b1, b2, n) != 0 )
        Weird("fragment_inconsistency");
    else
        Weird("fragment_overlap");
}

void FragReassembler::BlockInserted(DataBlockMap::const_iterator ) {
    auto it = block_list.Begin();

    if ( it->second.seq > 0 || ! frag_size )

        return;

    auto next = std::next(it);


    while ( next != block_list.End() ) {
        if ( it->second.upper != next->second.seq )
            break;

        ++it;
        ++next;
    }

    const auto& last = block_list.LastBlock();

    if ( next != block_list.End() ) {

        if ( it->second.upper >= frag_size ) {






            Weird("fragment_size_inconsistency");




            frag_size = it->second.upper;
        }
        else
            return;
    }

    else if ( last.upper > frag_size ) {
        Weird("fragment_size_inconsistency");
        frag_size = last.upper;
    }

    else if ( last.upper < frag_size )

        return;


    const uint64_t n = proto_hdr_len + frag_size;








    u_char* pkt = new u_char[n];
    memcpy(pkt, proto_hdr, proto_hdr_len);

    u_char* pkt_start = pkt;

    pkt += proto_hdr_len;

    for ( it = block_list.Begin(); it != block_list.End(); ++it ) {
        const auto& b = it->second;

        if ( it != block_list.Begin() ) {
            const auto& prev = std::prev(it)->second;




            if ( prev.upper < b.seq )
                break;
        }

        if ( b.upper > n ) {
            reporter->InternalWarning("bad fragment reassembly");
            DeleteTimer();
            Expire(run_state::network_time);
            delete[] pkt_start;
            return;
        }

        memcpy(&pkt[b.seq], b.block, b.upper - b.seq);
    }

    reassembled_pkt.reset();

    unsigned int version = (reinterpret_cast<const ip*>(pkt_start))->ip_v;

    if ( version == 4 ) {
        struct ip* reassem4 = reinterpret_cast<ip*>(pkt_start);
        reassem4->ip_len = htons(frag_size + proto_hdr_len);
        reassembled_pkt = std::make_shared<IP_Hdr>(reassem4, true, true, n);
        DeleteTimer();
    }

    else if ( version == 6 ) {
        struct ip6_hdr* reassem6 = reinterpret_cast<ip6_hdr*>(pkt_start);
        reassem6->ip6_plen = htons(frag_size + proto_hdr_len - 40);
        const IPv6_Hdr_Chain* chain = new IPv6_Hdr_Chain(reassem6, next_proto, n);
        reassembled_pkt = std::make_shared<IP_Hdr>(reassem6, true, n, chain, true);
        DeleteTimer();
    }

    else {
        reporter->InternalWarning("bad IP version in fragment reassembly: %d", version);
        delete[] pkt_start;
    }
}

void FragReassembler::Expire(double t) {
    block_list.Clear();
    expire_timer->ClearReassembler();
    expire_timer = nullptr;

    fragment_mgr->Remove(this);
}

void FragReassembler::DeleteTimer() {
    if ( expire_timer ) {
        expire_timer->ClearReassembler();
        timer_mgr->Cancel(expire_timer);
        expire_timer = nullptr;
    }
}

FragmentManager::~FragmentManager() { Clear(); }

FragReassembler* FragmentManager::NextFragment(double t, const std::shared_ptr<IP_Hdr>& ip, const u_char* pkt) {
    uint32_t frag_id = ip->ID();
    FragReassemblerKey key = std::make_tuple(ip->SrcAddr(), ip->DstAddr(), frag_id);

    FragReassembler* f = nullptr;
    auto it = fragments.find(key);
    if ( it != fragments.end() )
        f = it->second;

    if ( ! f ) {
        f = new FragReassembler(session_mgr, ip, pkt, key, t);
        fragments[key] = f;
        if ( fragments.size() > max_fragments )
            max_fragments = fragments.size();
        return f;
    }

    f->AddFragment(t, ip, pkt);
    return f;
}

void FragmentManager::Clear() {
    for ( const auto& entry : fragments )
        Unref(entry.second);

    fragments.clear();
}

void FragmentManager::Remove(detail::FragReassembler* f) {
    if ( ! f )
        return;

    if ( fragments.erase(f->Key()) == 0 )
        reporter->InternalWarning("fragment reassembler not in dict");

    Unref(f);
}

}
