





function is_string_binary(s: string): bool
	{
	return |gsub(s, /[\x00-\x7f]/, "")| * 100 / |s| >= 25;
	}









function string_escape(s: string, chars: string): string
	{
	s = subst_string(s, "\\", "\\\\");
	for ( c in chars )
		s = subst_string(s, c, cat("\\", c));
	return s;
	}








function cut_tail(s: string, tail_len: count): string
	{
	if ( tail_len > |s| )
		tail_len = |s|;
	return sub_bytes(s, 1, (|s| - tail_len) as count);
	}
