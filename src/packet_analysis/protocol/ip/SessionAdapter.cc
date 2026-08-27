

#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

#include "zeek/File.h"
#include "zeek/ZeekString.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

using namespace zeek::packet_analysis::IP;

void SessionAdapter::Done() {
    Analyzer::Done();
    for ( const auto& ta : tap_analyzers )
        ta->Done();
}

bool SessionAdapter::IsReuse(double t, const u_char* pkt) { return parent->IsReuse(t, pkt); }

void SessionAdapter::SetContentsFile(unsigned int , FilePtr ) {
    reporter->Error("analyzer type does not support writing to a contents file");
}

zeek::FilePtr SessionAdapter::GetContentsFile(unsigned int ) const {
    reporter->Error("analyzer type does not support writing to a contents file");
    return nullptr;
}

void SessionAdapter::PacketContents(const u_char* data, int len) {
    if ( packet_contents && len > 0 ) {
        zeek::String* cbs = new zeek::String(data, len, true);
        auto contents = make_intrusive<StringVal>(cbs);
        EnqueueConnEvent(packet_contents, ConnVal(), std::move(contents));
    }
}

void SessionAdapter::AddTapAnalyzer(TapAnalyzerPtr ta) {
    assert(! IsFinished());
    tap_analyzers.push_back(std::move(ta));
    tap_analyzers.back()->Init();
}

bool SessionAdapter::RemoveTapAnalyzer(const TapAnalyzer* ta) {

    for ( auto it = tap_analyzers.begin(); it != tap_analyzers.end(); ++it ) {
        if ( it->get() == ta ) {

            auto ptr{std::move(*it)};
            tap_analyzers.erase(it);
            ptr->Done();
            ptr.reset();
            return true;
        }
    }

    return false;
}

void SessionAdapter::TapPacket(const Packet* pkt, PacketAction action, SkipReason skip_reason) const {
    for ( const auto& ta : tap_analyzers )
        ta->TapPacket(*pkt, action, skip_reason);
}

void SessionAdapter::UpdateConnVal(RecordVal* conn_val) {
    Analyzer::UpdateConnVal(conn_val);

    for ( const auto& ta : tap_analyzers )
        ta->UpdateConnVal(conn_val);
}
