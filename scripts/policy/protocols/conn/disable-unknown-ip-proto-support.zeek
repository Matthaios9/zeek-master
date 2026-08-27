


@load base/protocols/conn
@load base/frameworks/analyzer/main

redef record Conn::Info$ip_proto -= { &log };

event zeek_init() {
	Analyzer::disable_analyzer(PacketAnalyzer::ANALYZER_UNKNOWN_IP_TRANSPORT);
}
