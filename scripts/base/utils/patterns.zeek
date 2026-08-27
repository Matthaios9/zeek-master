

module GLOBAL;



















function set_to_regex(ss: set[string], pat: string): pattern
	{
	local i: count = 0;
	local return_pat = "";
	for ( s in ss )
		{
		local tmp_pattern = convert_for_pattern(s);
		return_pat = ( i == 0 ) ?
			 tmp_pattern : cat(tmp_pattern, "|", return_pat);
		++i;
		}
	return string_to_pattern(sub(pat, /~~/, return_pat), F);
	}

type PatternMatchResult: record {

	matched: bool;

	str: string;

	off: count;
};













function match_pattern(s: string, p: pattern): PatternMatchResult
	{
	local a = split_string_n(s, p, T, 1);

	if ( |a| == 1 )

		return PatternMatchResult($matched = F, $str = "", $off = 0);
	else
		return PatternMatchResult($matched = T, $str = a[1], $off = |a[0]| + 1);
	}
