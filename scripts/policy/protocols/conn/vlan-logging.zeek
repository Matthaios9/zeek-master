

@load base/protocols/conn

module Conn;

redef record Info += {

	vlan: int      &log &optional;


	inner_vlan: int      &log &optional;
};




event connection_state_remove(c: connection)
	{
	if ( c?$vlan )
		c$conn$vlan = c$vlan;

	if ( c?$inner_vlan )
		c$conn$inner_vlan = c$inner_vlan;
	}
