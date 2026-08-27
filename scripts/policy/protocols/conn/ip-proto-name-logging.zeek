



@load base/protocols/conn

module Conn;

redef record Info += {

	ip_proto_name: string &log &optional;
};

event new_connection(c: connection) &priority=5 {
	if ( c$conn?$ip_proto && c$conn$ip_proto in IP::protocol_names )
		c$conn$ip_proto_name = IP::protocol_names[c$conn$ip_proto];
}
