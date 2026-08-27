module PacketAnalyzer::TEREDO;




@load base/bif/plugins/Zeek_Teredo.events.bif.zeek
@load base/bif/plugins/Zeek_Teredo.functions.bif


@load base/frameworks/analyzer/main


@load base/protocols/conn/removal-hooks

export {

	const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;


	const teredo_ports = { 3544/udp } &redef;
}


event zeek_init() &priority=20
	{
	PacketAnalyzer::register_protocol_detection(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_TEREDO);
	PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, PacketAnalyzer::ANALYZER_TEREDO, teredo_ports);
	}



hook finalize_teredo(c: connection)
	{
	remove_teredo_connection(c$id);
	}

event new_teredo_state(c: connection)
	{
	Conn::register_removal_hook(c, finalize_teredo);
	}
