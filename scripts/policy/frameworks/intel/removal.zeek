

@load base/frameworks/intel

module Intel;

export {
	redef record Intel::MetaData += {

		remove: bool &default=F;
	};
}

hook Intel::filter_item(item: Item)
	{
	if ( item$meta$remove )
		{
		Intel::remove(item);

		break;
		}
	}
