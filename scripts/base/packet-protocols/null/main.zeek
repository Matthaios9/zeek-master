module PacketAnalyzer::NULL;

const DLT_NULL : count = 0;

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_NULL, PacketAnalyzer::ANALYZER_NULL);






	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_NULL, 2, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_NULL, 24, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_NULL, 28, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_NULL, 30, PacketAnalyzer::ANALYZER_IP);
	}
