
@load base/protocols/conn

module CommunityID;

export {

	option seed: count = 0;



	option do_base64: bool = T;


	redef record Conn::Info += {
		community_id: string &optional &log;
	};
}

event new_connection(c: connection) &priority=5
	{
	c$conn$community_id = community_id_v1(c$id, CommunityID::seed, CommunityID::do_base64);
	}
