










module LogSQLite;

export {

	const set_separator = Log::set_separator &redef;


	const unset_field = Log::unset_field &redef;



	const empty_field = Log::empty_field &redef;


	type SQLiteSynchronous: enum {
		SQLITE_SYNCHRONOUS_DEFAULT,
		SQLITE_SYNCHRONOUS_OFF,
		SQLITE_SYNCHRONOUS_NORMAL,
		SQLITE_SYNCHRONOUS_FULL,
		SQLITE_SYNCHRONOUS_EXTRA,
	};


	type SQLiteJournalMode: enum {
		SQLITE_JOURNAL_MODE_DEFAULT,
		SQLITE_JOURNAL_MODE_DELETE,
		SQLITE_JOURNAL_MODE_TRUNCATE,
		SQLITE_JOURNAL_MODE_PERSIST,
		SQLITE_JOURNAL_MODE_MEMORY,
		SQLITE_JOURNAL_MODE_WAL,
		SQLITE_JOURNAL_MODE_OFF,
	};





	const synchronous = SQLITE_SYNCHRONOUS_DEFAULT &redef;







	const journal_mode = SQLITE_JOURNAL_MODE_DEFAULT &redef;
}
