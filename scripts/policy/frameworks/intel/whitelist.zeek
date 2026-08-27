

@load base/frameworks/intel

module Intel;

export {
	redef record Intel::MetaData += {

		whitelist: bool &default=F;
	};
}

hook Intel::extend_match(info: Info, s: Seen, items: set[Item]) &priority=9
	{
	local whitelisted = F;
	for ( item in items )
		{
		if ( item$meta$whitelist )
			{
			whitelisted = T;
			break;
			}
		}

	if ( whitelisted )

		break;
	}
