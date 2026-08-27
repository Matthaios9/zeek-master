





function extract_email_addrs_vec(str: string): string_vec
	{
	local addrs: vector of string = vector();

	local raw_addrs = find_all_ordered(str, /(^|[<,:[:blank:]])[^<,:[:blank:]@]+"@"[^>,;[:blank:]]+([>,;[:blank:]]|$)/);
	for ( i in raw_addrs )
		addrs += gsub(raw_addrs[i], /[<>,:;[:blank:]]/, "");

	return addrs;
	}







function extract_email_addrs_set(str: string): set[string]
	{
	local addrs: set[string] = set();

	local raw_addrs = find_all(str, /(^|[<,:[:blank:]])[^<,:[:blank:]@]+"@"[^>,;[:blank:]]+([>,;[:blank:]]|$)/);
	for ( raw_addr in raw_addrs )
		add addrs[gsub(raw_addr, /[<>,:;[:blank:]]/, "")];

	return addrs;
	}






function extract_first_email_addr(str: string): string
	{
	local addrs = extract_email_addrs_vec(str);
	if ( |addrs| > 0 )
		return addrs[0];
	else
		return "";
	}










function split_mime_email_addresses(line: string): set[string]
	{
	local output = string_set();
	local addrs = find_all(line, /(\"[^"]*\")?[^,]+@[^,]+/);
	for ( part in addrs )
		{
		add output[strip(part)];
		}
	return output;
	}
