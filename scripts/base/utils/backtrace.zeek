













function print_backtrace(show_args: bool &default=F,
                         one_line: bool &default=F,
                         one_line_delim: string &default="|",
                         skip: count &default=1,
                         to_file: file &default=open("/dev/stdout"))
	{
	local bt = backtrace();
	local vs: vector of string = vector();
	local orig_skip = skip;

	for ( i in bt )
		{
		if ( skip > 0 )
			{
			--skip;
			next;
			}

		local bte = bt[i];

		local info = fmt("%s(", bte$function_name);

		if ( show_args )
			for ( ai in bte$function_args )
				{
				local arg = bte$function_args[ai];

				if ( ai > 0 )
					info += ", ";

				info += fmt("%s: %s", arg$name, arg$type_name);

				if ( arg?$value )
					info += fmt(" = %s", arg$value);
				}

		info += ")";

		if ( bte?$file_location )
			info += fmt(" at %s:%s", bte$file_location, bte$line_location);

		vs += fmt("#%s: %s", i - orig_skip, info);
		}

	if ( one_line )
		{
		local line = "";

		for ( vsi in vs )
			{
			line += one_line_delim + " " + vs[vsi] + " ";

			if ( vsi == |vs| - 1 )
				line += one_line_delim;
			}

		print to_file, line;
		}
	else
		{
		for ( vsi in vs )
			print to_file, vs[vsi];
		}
	}
