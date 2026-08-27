


@load ./main

module Intel;

export {

	redef enum Type += {


		FILE_HASH,


		FILE_NAME,
	};


	redef record Seen += {


		f:              fa_file  &optional;



		fuid:           string   &optional;
	};



	redef record Info += {


		fuid:           string   &log &optional;



		file_mime_type: string   &log &optional;



		file_desc:      string   &log &optional;
	};
}


hook extend_match(info: Info, s: Seen, items: set[Item]) &priority=6
	{
	if ( s?$f )
		{
		s$fuid = s$f$id;

		if ( s$f?$conns && |s$f$conns| == 1 )
			{
			for ( _, c in s$f$conns )
				s$conn = c;
			}

		if ( ! info?$file_mime_type && s$f?$info && s$f$info?$mime_type )
			info$file_mime_type = s$f$info$mime_type;

		if ( ! info?$file_desc )
			info$file_desc = Files::describe(s$f);
		}

	if ( s?$fuid )
		info$fuid = s$fuid;
	}
