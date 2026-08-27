












@load base/utils/files

module Conn;

export {


	option extraction_prefix = "contents";



	option default_extract = F;
}

redef record connection += {
	extract_orig: bool &default=default_extract;
	extract_resp: bool &default=default_extract;
};

event connection_established(c: connection) &priority=-5
	{
	if ( c$extract_orig )
		{
		local orig_file = generate_extraction_filename(extraction_prefix, c, "orig.dat");
		local orig_f = open(orig_file);
		set_contents_file(c$id, CONTENTS_ORIG, orig_f);
		}

	if ( c$extract_resp )
		{
		local resp_file = generate_extraction_filename(extraction_prefix, c, "resp.dat");
		local resp_f = open(resp_file);
		set_contents_file(c$id, CONTENTS_RESP, resp_f);
		}
	}
