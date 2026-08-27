

@load base/frameworks/storage/main

module Storage::Backend::SQLite;

export {

	type Options: record {






		database_path: string;




		table_name: string;




		busy_timeout: interval &default=5 secs;







		pragma_commands: table[string] of string &ordered &default=table(
			["quick_check"] = "",
			["journal_mode"] = "WAL",
			["synchronous"] = "normal",
			["temp_store"] = "memory"
		) &ordered;





		pragma_timeout: interval &default=500 msec;



		pragma_wait_on_busy: interval &default=5 msec;
	};
}

redef record Storage::BackendOptions += {
	sqlite: Storage::Backend::SQLite::Options &optional;
};
