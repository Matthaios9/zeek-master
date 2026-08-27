@load base/frameworks/intel
@load ./where-locations

event file_new(f: fa_file) &group="Intel::FILE_NAME"
	{



	if ( f?$conns && |f$conns| > 0 )
		return;

	if ( f?$info && f$info?$filename )
		Intel::seen(Intel::Seen($indicator=f$info$filename,
		                        $indicator_type=Intel::FILE_NAME,
		                        $f=f,
		                        $where=Files::IN_NAME));
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=-5 &group="Intel::FILE_NAME"
	{

    if ( f$source == "SMB" )
        return;

	if ( f?$info && f$info?$filename )
		Intel::seen(Intel::Seen($indicator=f$info$filename,
		                        $indicator_type=Intel::FILE_NAME,
		                        $f=f,
		                        $where=Files::IN_NAME));
	}
