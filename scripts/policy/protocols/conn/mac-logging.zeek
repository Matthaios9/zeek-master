

@load base/protocols/conn

module Conn;

redef record Info += {

	orig_l2_addr: string	&log &optional;

	resp_l2_addr: string	&log &optional;
};




event connection_state_remove(c: connection)
	{
	if ( c$orig?$l2_addr )
		c$conn$orig_l2_addr = c$orig$l2_addr;

	if ( c$resp?$l2_addr )
		c$conn$resp_l2_addr = c$resp$l2_addr;
	}
