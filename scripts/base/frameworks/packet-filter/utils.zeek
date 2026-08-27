module PacketFilter;

export {






	global port_to_bpf: function(p: port): string;






	global sampling_filter: function(num_parts: count, this_part: count): string;













	global combine_filters: function(lfilter: string, op: string, rfilter: string): string;
}

function port_to_bpf(p: port): string
	{
	local tp = get_port_transport_proto(p);
	return cat(tp, " and ", fmt("port %d", p));
	}

function combine_filters(lfilter: string,  op: string, rfilter: string): string
	{
	if ( lfilter == "" && rfilter == "" )
		return "";
	else if ( lfilter == "" )
		return rfilter;
	else if ( rfilter == "" )
		return lfilter;
	else
		return fmt("(%s) %s (%s)", lfilter, op, rfilter);
	}

function sampling_filter(num_parts: count, this_part: count): string
	{
	local v4_filter = fmt("ip and ((ip[14:2]+ip[18:2]) - (%d*((ip[14:2]+ip[18:2])/%d)) == %d)", num_parts, num_parts, this_part);

	local v6_filter = fmt("ip6 and ((ip6[22:2]+ip6[38:2]) - (%d*((ip6[22:2]+ip6[38:2])/%d)) == %d)", num_parts, num_parts, this_part);
	return combine_filters(v4_filter, "or", v6_filter);
	}
