












function haversine_distance_ip(a1: addr, a2: addr): double
	{
	local loc1 = lookup_location(a1);
	local loc2 = lookup_location(a2);
	local miles: double;

	if ( loc1?$latitude && loc1?$longitude && loc2?$latitude && loc2?$longitude )
		miles = haversine_distance(loc1$latitude, loc1$longitude, loc2$latitude, loc2$longitude);
	else
		miles = -1.0;

	return miles;
	}
