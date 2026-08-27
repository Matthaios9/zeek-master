





@load ../main
@load base/frameworks/notice
@load base/utils/site

module Notice;

export {
	redef enum Action += {



		ACTION_ADD_GEODATA
	};

	redef record Info += {


		remote_location: geo_location  &log &optional;
	};



	option lookup_location_types: set[Notice::Type] = {};
}

hook policy(n: Notice::Info) &priority=10
	{
	if ( n$note in Notice::lookup_location_types )
		add n$actions[ACTION_ADD_GEODATA];
	}



hook notice(n: Notice::Info) &priority=10
	{
	if ( ACTION_ADD_GEODATA in n$actions &&
	     |Site::local_nets| > 0 &&
	     ! n?$remote_location )
		{
		if ( n?$src && ! Site::is_local_addr(n$src) )
			n$remote_location = lookup_location(n$src);
		else if ( n?$dst && ! Site::is_local_addr(n$dst) )
			n$remote_location = lookup_location(n$dst);
		}
	}
