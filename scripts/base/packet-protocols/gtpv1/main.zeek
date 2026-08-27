module PacketAnalyzer::GTPV1;




@load base/bif/plugins/Zeek_GTPv1.events.bif
@load base/bif/plugins/Zeek_GTPv1.functions.bif


@load base/frameworks/analyzer/main


@load base/protocols/conn/removal-hooks

export {

	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;


	const gtpv1_ports = { 2152/udp, 2123/udp } &redef;
}


event zeek_init() &priority=20
	{
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_GTPV1, gtpv1_ports);
	}



hook finalize_gtpv1(c: connection)
	{
	remove_gtpv1_connection(c$id);
	}

event new_gtpv1_state(c: connection)
	{
	Conn::register_removal_hook(c, finalize_gtpv1);
	}
