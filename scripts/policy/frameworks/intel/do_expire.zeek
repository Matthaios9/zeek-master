

@load base/frameworks/intel

module Intel;

redef Intel::item_expiration = 10min;

hook item_expired(indicator: string, indicator_type: Type,
	metas: set[MetaData]) &priority=-10
	{

	break;
	}
