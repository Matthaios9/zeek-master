module PacketAnalyzer;

@load base/frameworks/analyzer/main.zeek

export {

















	global register_for_ports: function(parent: PacketAnalyzer::Tag,
	                                    child: PacketAnalyzer::Tag,
	                                    server_ports: set[port],
	                                    non_server_ports: set[port] &default=set()) : bool;











	global register_for_port: function(parent: PacketAnalyzer::Tag,
	                                   child: PacketAnalyzer::Tag,
	                                   p: port) : bool;
}

function register_for_ports(parent: PacketAnalyzer::Tag,
                            child: PacketAnalyzer::Tag,
                            server_ports: set[port],
                            non_server_ports: set[port] &default=set()) : bool
	{
	local rc = T;

	for ( p in server_ports )
		{
		if ( ! register_for_port(parent, child, p) )
			rc = F;
		}

	for ( p in non_server_ports )
		{
		if ( ! register_for_port(parent, child, p) )
			rc = F;
		}


	likely_server_ports += server_ports;

	return rc;
	}

function register_for_port(parent: PacketAnalyzer::Tag,
                           child: PacketAnalyzer::Tag,
                           p: port) : bool
	{
	register_packet_analyzer(parent, p as count, child);

	if ( child !in Analyzer::ports )
		Analyzer::ports[child] = set();

	add Analyzer::ports[child][p];
	return T;
	}
