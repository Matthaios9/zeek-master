@load frameworks/intel/seen
@load base/frameworks/reporter

module Intel;

export {














	const manage_seen_event_groups = T &redef;
}

global intel_type_counts: table[Intel::Type] of count &default=0;

event zeek_init()
	{

	if ( ! manage_seen_event_groups )
		return;




	for ( name in enum_names(Intel::Type) )
		{
		if ( has_event_group(name) )
			disable_event_group(name);
		}
	}

hook Intel::indicator_inserted(v: string, t: Intel::Type)
	{
	++intel_type_counts[t];

	if ( ! manage_seen_event_groups )
		return;


	if ( intel_type_counts[t] == 1 )
		{
		local name = cat(t);

		if ( has_event_group(name) )
			enable_event_group(name);
		}
	}

hook Intel::indicator_removed(v: string, t: Intel::Type)
	{
	--intel_type_counts[t];

	if ( ! manage_seen_event_groups )
		return;


	if ( intel_type_counts[t] == 0 )
		{
		local name = cat(t);

		if ( has_event_group(name) )
			disable_event_group(name);
		}
	}
