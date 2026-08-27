

@load base/protocols/conn

module Conn;

redef record Info += {

	pppoe_session_id: count &log &optional;
};



event new_connection(c: connection)
	{
	local session_id = PacketAnalyzer::PPPoE::session_id();


	if ( session_id == 0xFFFFFFFF )
		return;

	c$conn$pppoe_session_id = session_id;
	}
