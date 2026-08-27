@load base/frameworks/files
@load base/utils/paths

module FileExtract;

export {

	const prefix = "./extract_files/" &redef;



	option default_limit = 104857600;








	option default_limit_includes_missing = T;

	redef record Files::Info += {

		extracted: string &optional &log;



		extracted_cutoff: bool &optional &log;


		extracted_size: count &optional &log;
	};

	redef record Files::AnalyzerArgs += {






		extract_filename: string &optional;





		extract_limit: count &default=default_limit;







		extract_limit_includes_missing: bool &default=default_limit_includes_missing;
	};











	global set_limit: function(f: fa_file, args: Files::AnalyzerArgs, n: count): bool;
}

function set_limit(f: fa_file, args: Files::AnalyzerArgs, n: count): bool
	{
	return __set_limit(f$id, args, n);
	}

function on_add(f: fa_file, args: Files::AnalyzerArgs)
	{
	if ( ! args?$extract_filename )
		args$extract_filename = cat("extract-", f$last_active, "-", f$source,
		                            "-", f$id);

	f$info$extracted = args$extract_filename;
	args$extract_filename = build_path_compressed(prefix, args$extract_filename);
	f$info$extracted_cutoff = F;
	mkdir(prefix);
	}

event file_extraction_limit(f: fa_file, args: Files::AnalyzerArgs, limit: count, len: count) &priority=10
	{
	f$info$extracted_cutoff = T;
	f$info$extracted_size = limit;
	}

event zeek_init() &priority=10
	{
	Files::register_analyzer_add_callback(Files::ANALYZER_EXTRACT, on_add);
	}
