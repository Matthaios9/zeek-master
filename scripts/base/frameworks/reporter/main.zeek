












module Reporter;

export {

	redef enum Log::ID += { LOG };


	global log_policy: Log::PolicyHook;


	type Info: record {

		ts:       time   &log;




		level:    Level  &log;


		message:  string &log;


		location: string &log &optional;
	};
}

event zeek_init() &priority=5
	{
	Log::create_stream(Reporter::LOG, Log::Stream($columns=Info, $path="reporter", $policy=log_policy));
	}

event reporter_info(t: time, msg: string, location: string) &priority=-5
	{
	Log::write(Reporter::LOG, Info($ts=t, $level=INFO, $message=msg, $location=location));
	}

event reporter_warning(t: time, msg: string, location: string) &priority=-5
	{
	Log::write(Reporter::LOG, Info($ts=t, $level=WARNING, $message=msg, $location=location));
	}

event reporter_error(t: time, msg: string, location: string) &priority=-5
	{
	Log::write(Reporter::LOG, Info($ts=t, $level=ERROR, $message=msg, $location=location));
	}
