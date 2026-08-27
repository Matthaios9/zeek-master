




@load ./config

module Management::Log;

export {

	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;


	type Level: enum {
		DEBUG = 10,
		INFO = 20,
		WARNING = 30,
		ERROR = 40,
	};


	type Info: record {

		ts: time;

		node: string;

		level: string;

		role: string;

		message:  string;
	} &log;



	global level = INFO &redef;





	global debug: function(message: string);





	global info: function(message: string);





	global warning: function(message: string);






	global error: function(message: string);
}




global l2s: table[Level] of string = {
	[DEBUG] = "DEBUG",
	[INFO] = "INFO",
	[WARNING] = "WARNING",
	[ERROR] = "ERROR",
};

global r2s: table[Management::Role] of string = {
	[Management::AGENT] = "AGENT",
	[Management::CONTROLLER] = "CONTROLLER",
	[Management::NODE] = "NODE",
};

function debug(message: string)
	{
	if ( level as int > DEBUG as int )
		return;

	local node = Supervisor::node();
	Log::write(LOG, Info($ts=network_time(), $node=node$name, $level=l2s[DEBUG],
	                     $role=r2s[Management::role], $message=message));
	}

function info(message: string)
	{
	if ( level as int > INFO as int )
		return;

	local node = Supervisor::node();
	Log::write(LOG, Info($ts=network_time(), $node=node$name, $level=l2s[INFO],
	                     $role=r2s[Management::role], $message=message));
	}

function warning(message: string)
	{
	if ( level as int > WARNING as int )
		return;

	local node = Supervisor::node();
	Log::write(LOG, Info($ts=network_time(), $node=node$name, $level=l2s[WARNING],
	                     $role=r2s[Management::role], $message=message));
	}

function error(message: string)
	{
	if ( level as int > ERROR as int )
		return;

	local node = Supervisor::node();
	Log::write(LOG, Info($ts=network_time(), $node=node$name, $level=l2s[ERROR],
	                     $role=r2s[Management::role], $message=message));
	}


event zeek_init() &priority=5
	{
	if ( ! Supervisor::is_supervised() )
		return;

	local node = Supervisor::node();




	local stream = Log::Stream($columns=Info, $path=fmt("management-%s", node$name),
	                           $policy=log_policy);

	Log::create_stream(Management::Log::LOG, stream);
	}
