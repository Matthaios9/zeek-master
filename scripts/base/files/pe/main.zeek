module PE;

@load ./consts

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {

		ts:                  time              &log;

		id:                  string            &log;

		machine:             string            &log &optional;

		compile_ts:          time              &log &optional;

		os:                  string            &log &optional;

		subsystem:           string            &log &optional;

		is_exe:              bool              &log &default=T;

		is_64bit:            bool              &log &default=T;

		uses_aslr:           bool              &log &default=F;

		uses_dep:            bool              &log &default=F;

		uses_code_integrity: bool              &log &default=F;

		uses_seh:            bool              &log &default=T;

		has_import_table:    bool              &log &optional;

		has_export_table:    bool              &log &optional;

		has_cert_table:      bool              &log &optional;

		has_debug_data:      bool              &log &optional;

		section_names:       vector of string  &log &optional;
	};


	global log_pe: event(rec: Info);


	global set_file: hook(f: fa_file);
}

redef record fa_file += {
	pe: Info &optional;
};

const pe_mime_types = { "application/x-dosexec" };

event zeek_init() &priority=5
	{
	Files::register_for_mime_types(Files::ANALYZER_PE, pe_mime_types);
	Log::create_stream(LOG, Log::Stream($columns=Info, $ev=log_pe, $path="pe", $policy=log_policy));
	}

hook set_file(f: fa_file) &priority=5
	{
	if ( ! f?$pe )
		f$pe = PE::Info($ts=f$info$ts, $id=f$id);
	}

event pe_dos_header(f: fa_file, h: PE::DOSHeader) &priority=5
	{
	hook set_file(f);
	}

event pe_file_header(f: fa_file, h: PE::FileHeader) &priority=5
	{
	hook set_file(f);

	f$pe$machine    = machine_types[h$machine];
	f$pe$compile_ts = h$ts;
	f$pe$is_exe     = ( h$optional_header_size > 0 );

	for ( c in h$characteristics )
		{
		if ( file_characteristics[c] == "32BIT_MACHINE" )
			f$pe$is_64bit = F;
		}
	}

event pe_optional_header(f: fa_file, h: PE::OptionalHeader) &priority=5
	{
	hook set_file(f);


	if ( ! f$pe$is_exe )
		return;

	f$pe$os        = os_versions[h$os_version_major, h$os_version_minor];
	f$pe$subsystem = windows_subsystems[h$subsystem];

	for ( c in h$dll_characteristics )
		{
		if ( dll_characteristics[c] == "DYNAMIC_BASE" )
			f$pe$uses_aslr = T;
		if ( dll_characteristics[c] == "FORCE_INTEGRITY" )
			f$pe$uses_code_integrity = T;
		if ( dll_characteristics[c] == "NX_COMPAT" )
			f$pe$uses_dep = T;
		if ( dll_characteristics[c] == "NO_SEH" )
			f$pe$uses_seh = F;
		}

	f$pe$has_export_table = (|h$table_sizes| > 0 && h$table_sizes[0] > 0);
	f$pe$has_import_table = (|h$table_sizes| > 1 && h$table_sizes[1] > 0);
	f$pe$has_cert_table   = (|h$table_sizes| > 4 && h$table_sizes[4] > 0);
	f$pe$has_debug_data   = (|h$table_sizes| > 6 && h$table_sizes[6] > 0);
	}

event pe_section_header(f: fa_file, h: PE::SectionHeader) &priority=5
	{
	hook set_file(f);


	if ( ! f$pe$is_exe )
		return;

	if ( ! f$pe?$section_names )
		f$pe$section_names = vector();
	f$pe$section_names += h$name;
	}

event file_state_remove(f: fa_file) &priority=-5
	{
	if ( f?$pe && f$pe?$machine )
		Log::write(LOG, f$pe);
	}
