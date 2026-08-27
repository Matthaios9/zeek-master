


@load base/protocols/conn
@load base/frameworks/notice
@load policy/protocols/conn/community-id-logging

module CommunityID::Notice;

export {



	option enabled: bool = T;

	redef record Notice::Info += {
		community_id: string &optional &log;
	};
}

hook Notice::notice(n: Notice::Info)
	{
	if ( CommunityID::Notice::enabled && n?$conn && n$conn?$conn )
		{
		local info = n$conn$conn;


		if ( info?$community_id )
			n$community_id = info$community_id;
		}
	}
