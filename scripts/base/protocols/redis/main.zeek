@load base/protocols/conn/removal-hooks
@load base/frameworks/signatures

@load ./spicy-events

module Redis;

export {

	redef enum Log::ID += { LOG };


	const ports = {6379/tcp} &redef;


	type Info: record {

		ts: time &log;

		uid: string &log;

		id: conn_id &log;

		cmd: Command &log;

		success: bool &log &optional;

		reply: ReplyData &log &optional;
	};


	global log_policy: Log::PolicyHook;

	global finalize_redis: Conn::RemovalHook;




	type NoReplyRange: record {
		begin: count;
		end: count &optional;
	};

	type RESPVersion: enum {
		RESP2,
		RESP3
	};

	type State: record {

		pending: table[count] of Info;

		current_command: count &default=0;

		current_reply: count &default=0;



		no_reply_ranges: vector of NoReplyRange;


		skip_commands: set[count];


		violation: bool &default=F;

		subscribed_mode: bool &default=F;

		resp_version: RESPVersion &default=RESP2;
	};



	option max_pending_commands = 10000;


	global enter_subscribed_mode = [RedisCommand_PSUBSCRIBE,
	    RedisCommand_SSUBSCRIBE, RedisCommand_SUBSCRIBE];


	global exit_subscribed_mode = [RedisCommand_RESET, RedisCommand_QUIT];


	global no_response_commands = [RedisCommand_PSUBSCRIBE,
	    RedisCommand_PUNSUBSCRIBE, RedisCommand_SSUBSCRIBE,
	    RedisCommand_SUBSCRIBE, RedisCommand_SUNSUBSCRIBE,
	    RedisCommand_UNSUBSCRIBE];



	const max_value_size: count = 250 &redef;
}

redef record connection += {
	redis: Info &optional;
	redis_state: State &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(Redis::LOG, Log::Stream($columns=Info, $path="redis",
	    $policy=log_policy));

	Analyzer::register_for_ports(Analyzer::ANALYZER_REDIS, ports);
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag,
    info: AnalyzerViolationInfo)
	{
	if ( atype == Analyzer::ANALYZER_REDIS && info?$c && info$c?$redis_state )
		{
		info$c$redis_state$violation = T;
		}
	}

function new_redis_info(c: connection): Info
	{
	return Info($ts=network_time(), $uid=c$uid, $id=c$id);
	}

function make_new_state(c: connection)
	{
	local s: State;
	c$redis_state = s;
	Conn::register_removal_hook(c, finalize_redis);
	}

function set_state(c: connection, is_orig: bool)
	{
	if ( ! c?$redis_state )
		make_new_state(c);

	local current: count;
	if ( is_orig )
		current = c$redis_state$current_command;
	else
		current = c$redis_state$current_reply;

	if ( current !in c$redis_state$pending )
		c$redis_state$pending[current] = new_redis_info(c);

	c$redis = c$redis_state$pending[current];
	}


function is_last_interval_closed(c: connection): bool
	{
	return |c$redis_state$no_reply_ranges| == 0 ||
	    c$redis_state$no_reply_ranges[-1]?$end;
	}

event hello_command(c: connection, hello: HelloCommand)
	{
	if ( ! c?$redis_state )
		make_new_state(c);

	if ( hello?$requested_resp_version && hello$requested_resp_version == "3" )
		c$redis_state$resp_version = RESP3;
	}

event command(c: connection, cmd: Command)
	{
	if ( ! c?$redis_state )
		make_new_state(c);

	if ( max_pending_commands > 0
	    && |c$redis_state$pending| > max_pending_commands )
		{
		Reporter::conn_weird("Redis_excessive_pipelining", c);



		delete c$redis_state;
		return;
		}

	++c$redis_state$current_command;

	if ( cmd?$known )
		{
		if ( c$redis_state$resp_version == RESP2 )
			{
			local should_enter = cmd$known in enter_subscribed_mode;
			local should_exit = cmd$known in exit_subscribed_mode;
			c$redis_state$subscribed_mode = should_enter && ! should_exit;


			if ( should_enter && should_exit )
				Reporter::conn_weird("Redis_command_enter_exit_subscribed_mode", c, cat(
				    cmd$known));
			}
		if ( cmd$known in no_response_commands || c$redis_state$subscribed_mode )
			{
			add c$redis_state$skip_commands[c$redis_state$current_command];
			}
		}




	if ( cmd?$known && cmd$known == RedisCommand_CLIENT )
		{

		if ( |cmd$raw| == 3 )
			{
			if ( to_lower(cmd$raw[2]) == "on" )
				{

				if ( |c$redis_state$no_reply_ranges| > 0 )
					{
					local range = c$redis_state$no_reply_ranges[-1];
					if ( ! range?$end )
						{
						range$end = c$redis_state$current_command;
						}
					}
				}
			if ( to_lower(cmd$raw[2]) == "off" )
				{

				if ( is_last_interval_closed(c) )
					{
					c$redis_state$no_reply_ranges += NoReplyRange(
					    $begin=c$redis_state$current_command);
					}
				}
			if ( to_lower(cmd$raw[2]) == "skip" )
				{
				if ( is_last_interval_closed(c) )

					c$redis_state$no_reply_ranges += NoReplyRange(
					    $begin=c$redis_state$current_command, $end=c$redis_state$current_command + 2);
				}
			}
		}

	set_state(c, T);

	c$redis$cmd = cmd;
	}



function reply_num(c: connection): count
	{
	local resp_num = c$redis_state$current_reply + 1;
	local result = resp_num;
	for ( i in c$redis_state$no_reply_ranges )
		{
		local range = c$redis_state$no_reply_ranges[i];
		if ( ! range?$end && resp_num > range$begin )
			{ }
		if ( range?$end && resp_num >= range$begin && resp_num < range$end )
			result = range$end;
		}


	while ( result in c$redis_state$skip_commands )
		{
		delete c$redis_state$skip_commands[result];
		result += 1;
		}

	return result;
	}


function log_from(c: connection, previous_reply_num: count)
	{


	while ( previous_reply_num < c$redis_state$current_reply )
		{
		if ( previous_reply_num == 0 )
			{
			++previous_reply_num;
			next;
			}

		if ( previous_reply_num in c$redis_state$pending &&
		    c$redis_state$pending[previous_reply_num]?$cmd )
			{
			Log::write(Redis::LOG, c$redis_state$pending[previous_reply_num]);
			delete c$redis_state$pending[previous_reply_num];
			}
		previous_reply_num += 1;
		}

	if ( c$redis?$cmd )
		{
		Log::write(Redis::LOG, c$redis);
		delete c$redis_state$pending[c$redis_state$current_reply];
		}
	}

event reply(c: connection, data: ReplyData)
	{
	if ( ! c?$redis_state )
		make_new_state(c);


	if ( data$min_protocol_version == 3 )
		{
		c$redis_state$resp_version = RESP3;
		c$redis_state$subscribed_mode = F;
		}

	if ( c$redis_state$subscribed_mode )
		{
		event server_push(c, data);
		return;
		}

	local previous_reply_num = c$redis_state$current_reply;
	c$redis_state$current_reply = reply_num(c);
	set_state(c, F);

	c$redis$reply = data;
	c$redis$success = T;
	log_from(c, previous_reply_num);


	if ( c$redis_state$current_command == c$redis_state$current_reply )
		clear_table(c$redis_state$skip_commands);
	}

event error(c: connection, data: ReplyData)
	{
	if ( ! c?$redis_state )
		make_new_state(c);

	local previous_reply_num = c$redis_state$current_reply;
	c$redis_state$current_reply = reply_num(c);
	set_state(c, F);

	c$redis$reply = data;
	c$redis$success = F;
	log_from(c, previous_reply_num);
	}

hook finalize_redis(c: connection)
	{
	if ( ! c?$redis_state )
		{

		return;
		}

	if ( c$redis_state$violation )
		{

		return;
		}


	if ( c$redis_state$current_reply != 0 )
		{
		for ( r, info in c$redis_state$pending )
			{

			if ( r == 0 )
				next;
			Log::write(Redis::LOG, info);
			}
		}
	}
