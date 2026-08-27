







function extract_count(s: string, get_first: bool &default=T): count
	{
	local extract_num_pattern = /[0-9]+/;
	if ( get_first )
		{
		local first_parts = split_string_n(s, extract_num_pattern, T, 1);
		if ( 1 in first_parts )
			return first_parts[1] as count;
		}
	else
		{
		local last_parts = split_string_all(s, extract_num_pattern);
		if ( |last_parts| > 1 )
			return last_parts[|last_parts|-2] as count;
		}
	return 0;
	}
