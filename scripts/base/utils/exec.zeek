

@load base/frameworks/input

module Exec;

export {
	type Command: record {



		cmd:         string;

		stdin:       string      &default="";


		read_files:  set[string] &optional;

		uid: string &default=unique_id("");
	};

	type Result: record {

		exit_code:    count            &default=0;

		signal_exit:  bool             &default=F;

		stdout:       vector of string &optional;

		stderr:       vector of string &optional;


		files:        table[string] of string_vec &optional;
	};









	global run: function(cmd: Command): Result;
}


global results: table[string] of Result;
global pending_commands: set[string];
global pending_files: table[string] of set[string];

type OneLine: record {
	s: string;
	is_stderr: bool;
};

type FileLine: record {
	s: string;
};

event Exec::line(description: Input::EventDescription, tpe: Input::Event, s: string, is_stderr: bool)
	{
	local result = results[description$name];
	if ( is_stderr )
		{
		if ( ! result?$stderr )
			result$stderr = vector(s);
		else
			result$stderr += s;
		}
	else
		{
		if ( ! result?$stdout )
			result$stdout = vector(s);
		else
			result$stdout += s;
		}
	}

event Exec::file_line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	local parts = split_string1(description$name, /_/);
	local name = parts[0];
	local track_file = parts[1];

	local result = results[name];
	if ( ! result?$files )
		result$files = table();

	if ( track_file !in result$files )
		result$files[track_file] = vector(s);
	else
		result$files[track_file] += s;
	}

event Input::end_of_data(orig_name: string, source:string)
	{
	local name = orig_name;
	local parts = split_string1(name, /_/);
	name = parts[0];

	if ( name !in pending_commands || |parts| < 2 )
		return;

	local track_file = parts[1];



	local result = results[name];
	if ( ! result?$files )
		result$files = table();

	if ( track_file !in result$files )
		result$files[track_file] = vector();

	Input::remove(orig_name);

	if ( name !in pending_files )
		delete pending_commands[name];
	else
		{
		delete pending_files[name][track_file];
		if ( |pending_files[name]| == 0 )
			delete pending_commands[name];
		system(fmt("rm %s", safe_shell_quote(track_file)));
		}
	}

event InputRaw::process_finished(name: string, source:string, exit_code:count, signal_exit:bool)
	{
	if ( name !in pending_commands )
		return;




	results[name]$exit_code = exit_code;
	results[name]$signal_exit = signal_exit;

	if ( name !in pending_files || |pending_files[name]| == 0 )

		delete pending_commands[name];
	else
		for ( read_file in pending_files[name] )
			Input::add_event(Input::EventDescription($source=fmt("%s", read_file),
			                                         $name=fmt("%s_%s", name, read_file),
			                                         $reader=Input::READER_RAW,
			                                         $want_record=F,
			                                         $fields=FileLine,
			                                         $ev=Exec::file_line));
	}

function run(cmd: Command): Result
	{
	add pending_commands[cmd$uid];
	results[cmd$uid] = [];

	if ( cmd?$read_files )
		{
		for ( read_file in cmd$read_files )
			{
			if ( cmd$uid !in pending_files )
				pending_files[cmd$uid] = set();
			add pending_files[cmd$uid][read_file];
			}
		}

	local config_strings: table[string] of string = {
		["stdin"]       = cmd$stdin,
		["read_stderr"] = "1",
	};
	Input::add_event(Input::EventDescription($name=cmd$uid,
	                                         $source=fmt("%s |", cmd$cmd),
	                                         $reader=Input::READER_RAW,
	                                         $mode=Input::STREAM,
	                                         $fields=Exec::OneLine,
	                                         $ev=Exec::line,
	                                         $want_record=F,
	                                         $config=config_strings));

	return when [cmd] ( cmd$uid !in pending_commands )
		{
		local result = results[cmd$uid];
		delete results[cmd$uid];
		return result;
		}
	}

event zeek_done()
	{

	for ( uid in pending_files )
		for ( fname in pending_files[uid] )
			system(fmt("rm %s", safe_shell_quote(fname)));
	}
