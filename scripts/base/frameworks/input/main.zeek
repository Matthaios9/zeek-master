


module Input;

export {

	type Event: enum {

		EVENT_NEW = 0,

		EVENT_CHANGED = 1,

		EVENT_REMOVED = 2,
	};


	type Mode: enum {

		MANUAL = 0,

		REREAD = 1,

		STREAM = 2
	};


	option default_reader = READER_ASCII;


	option default_mode = MANUAL;




	const separator = "\t" &redef;




	const set_separator = "," &redef;



	const empty_field = "(empty)" &redef;



	const unset_field = "-" &redef;






	const accept_unsupported_types = F &redef;


	type TableDescription: record {




		source: string;


		reader: Reader &default=default_reader;


		mode: Mode &default=default_mode;



		name: string;




		destination: any;


		idx: any;



		val: any &optional;




		want_record: bool &default=T;






		ev: any &optional;






		pred: function(typ: Input::Event, left: any, right: any): bool &optional;










		error_ev: any &optional;




		config: table[string] of string &default=table();
	};


	type EventDescription: record {




		source: string;


		reader: Reader &default=default_reader;


		mode: Mode &default=default_mode;


		name: string;





		fields: any;





		want_record: bool &default=T;







		ev: any;










		error_ev: any &optional;




		config: table[string] of string &default=table();
	};



	type AnalysisDescription: record {


		source: string;




		reader: Reader &default=Input::READER_BINARY;


		mode: Mode &default=default_mode;






		name: string;




		config: table[string] of string &default=table();
	};






	global add_table: function(description: Input::TableDescription) : bool;






	global add_event: function(description: Input::EventDescription) : bool;








	global add_analysis: function(description: Input::AnalysisDescription) : bool;






	global remove: function(id: string) : bool;






	global force_update: function(id: string) : bool;







	global end_of_data: event(name: string, source: string);
}

@load base/bif/input.bif


module Input;

function add_table(description: Input::TableDescription) : bool
	{
	return __create_table_stream(description);
	}

function add_event(description: Input::EventDescription) : bool
	{
	return __create_event_stream(description);
	}

function add_analysis(description: Input::AnalysisDescription) : bool
	{
	return __create_analysis_stream(description);
	}

function remove(id: string) : bool
	{
	return __remove_stream(id);
	}

function force_update(id: string) : bool
	{
	return __force_update(id);
	}
