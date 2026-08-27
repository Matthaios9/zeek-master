@load base/frameworks/files
@load ./main

module SMB;

export {

	global get_file_handle: function(c: connection, is_orig: bool): string;


	global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
	{
	if ( ! (c$smb_state?$current_file &&
	        (c$smb_state$current_file?$name ||
	         c$smb_state$current_file?$path)) )
		{

		return "";
		}
	local current_file = c$smb_state$current_file;
	local path_name = current_file?$path ? current_file$path : "";
	local file_name = current_file?$name ? current_file$name : "";



	local last_mod  = cat(current_file?$times ? current_file$times$modified_raw : 0);



	return clean(cat(Analyzer::ANALYZER_SMB, c$id$orig_h, c$id$resp_h, path_name, file_name, last_mod));
	}

function describe_file(f: fa_file): string
	{

	if ( f$source != "SMB" )
		return "";

	for ( _, c in f$conns )
		{
		if ( c?$smb_state && c$smb_state?$current_file && c$smb_state$current_file?$name )
			return c$smb_state$current_file$name;
		}
	return "";
	}

event zeek_init() &priority=5
	{
	Files::register_protocol(Analyzer::ANALYZER_SMB,
	                         Files::ProtoRegistration($get_file_handle = SMB::get_file_handle,
	                                                  $describe        = SMB::describe_file ));
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
	{
	if ( c?$smb_state && c$smb_state?$current_file )
		{
		c$smb_state$current_file$fuid = f$id;

		if ( c$smb_state$current_file$size > 0 )
			f$total_bytes = c$smb_state$current_file$size;

		if ( c$smb_state$current_file?$name )
			f$info$filename = c$smb_state$current_file$name;
		write_file_log(c$smb_state);
		}
	}
