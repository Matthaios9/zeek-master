module PacketAnalyzer::Geneve;

export {




	const geneve_ports: set[port] = { 6081/udp } &redef;


	type Option: record {

		class: count;

		critical: bool;

		typ: count;

		data: string;
	};
}

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_GENEVE, geneve_ports);





	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GENEVE, 0x6558, PacketAnalyzer::ANALYZER_ETHERNET);


	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GENEVE, 0x0800, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GENEVE, 0x86DD, PacketAnalyzer::ANALYZER_IP);
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GENEVE, 0x0806, PacketAnalyzer::ANALYZER_ARP);
	}

module GLOBAL;

type geneve_options_vec: vector of PacketAnalyzer::Geneve::Option;
type geneve_options_vec_vec: vector of geneve_options_vec;
