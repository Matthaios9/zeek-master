









@prefixes += cluster-logger


redef Log::enable_local_logging = T;


redef Log::enable_remote_logging = F;


redef Log::default_rotation_interval = 1 hrs;


redef Log::default_mail_alarms_interval = 24 hrs;


global archiver_log_metadata: table[string] of string &redef;





@if ( Cluster::get_node_count(Cluster::LOGGER) > 1 )
redef archiver_log_metadata += {
	["log_suffix"] = Cluster::node,
};
@endif


function archiver_encode_log_metadata(tbl: table[string] of string): string
	{
	local metadata_vec: vector of string;
	for ( k, v in tbl )
		{
		if ( |v| == 0 )
			next;

		if ( /[,=]/ in k || /[,=]/ in v )
			{
			Reporter::warning(fmt("Invalid log_metadata: k='%s' v='%s'", k, v));
			next;
			}

		metadata_vec += fmt("%s=%s", strip(k), strip(v));
		}

	return join_string_vec(metadata_vec, ",");
	}




function archiver_rotation_format_func(ri: Log::RotationFmtInfo): Log::RotationPath
	{
	local open_str = strftime(Log::default_rotation_date_format, ri$open);
	local close_str = strftime(Log::default_rotation_date_format, ri$close);
	local base = fmt("%s__%s__%s__", ri$path, open_str, close_str);

	if ( |archiver_log_metadata| > 0 )
		base = fmt("%s%s__", base, archiver_encode_log_metadata(archiver_log_metadata));

	local rval = Log::RotationPath($file_basename=base);
	return rval;
	}

@if ( Supervisor::is_supervised() )

redef Log::default_rotation_dir = "log-queue";

redef Log::rotation_format_func = archiver_rotation_format_func;

redef LogAscii::enable_leftover_log_rotation = T;
@else


redef Log::default_rotation_postprocessor_cmd = "archive-log";

@endif
