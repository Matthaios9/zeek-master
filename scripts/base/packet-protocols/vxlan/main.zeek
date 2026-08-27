module PacketAnalyzer::VXLAN;

export {


        const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_ETHERNET &redef;





	const vxlan_ports: set[port] = { 4789/udp } &redef;
}

event zeek_init() &priority=20
	{
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_VXLAN, vxlan_ports);
	}
