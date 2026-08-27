

module Broker;

export {


	const default_port = 9999/tcp &redef;





	const default_listen_retry = 1sec &redef;




	const default_listen_address = getenv("ZEEK_DEFAULT_LISTEN_ADDRESS") &redef;






	const default_connect_retry = 1sec &redef;





	const disable_ssl = F &redef;




	const ssl_cafile = "" &redef;




	const ssl_capath = "" &redef;




	const ssl_certificate = "" &redef;




	const ssl_passphrase = "" &redef;




	const ssl_keyfile = "" &redef;



	const log_batch_size = 400 &redef;



	const log_batch_interval = 1sec &redef;



	const max_threads = 1 &redef;




	const peer_buffer_size = 8192 &redef;






	const peer_overflow_policy = "drop_oldest" &redef;



	const buffer_stats_reset_interval = 1min &redef;










	const scheduler_policy = "sharing" &redef;



	const moderate_sleep = 16 msec &redef;



	const relaxed_sleep = 64 msec &redef;



	const aggressive_polls = 5 &redef;



	const moderate_polls = 5 &redef;



	const aggressive_interval = 4 &redef;



	const moderate_interval = 2 &redef;



	const relaxed_interval = 1 &redef;


	const forward_messages = F &redef;






	option peer_counts_as_iosource = T;



	const default_log_topic_prefix = "zeek/logs/" &redef;


	function default_log_topic(id: Log::ID, path: string): string
		{
		return default_log_topic_prefix + cat(id);
		}












	const log_topic: function(id: Log::ID, path: string): string = default_log_topic &redef;


	type LogSeverityLevel: enum {

		LOG_CRITICAL,

		LOG_ERROR,

		LOG_WARNING,

		LOG_INFO,

		LOG_VERBOSE,

		LOG_DEBUG,
	};


	const log_severity_level = LOG_WARNING &redef;


	const log_stderr_severity_level = LOG_CRITICAL &redef;

	type ErrorCode: enum {

		UNSPECIFIED = 1,

		PEER_INCOMPATIBLE = 2,

		PEER_INVALID = 3,

		PEER_UNAVAILABLE = 4,

		PEER_DISCONNECT_DURING_HANDSHAKE = 5,

		PEER_TIMEOUT = 6,

		MASTER_EXISTS = 7,

		NO_SUCH_MASTER = 8,

		NO_SUCH_KEY = 9,

		REQUEST_TIMEOUT = 10,

		TYPE_CLASH = 11,

		INVALID_DATA = 12,

		BACKEND_FAILURE = 13,

		STALE_DATA = 14,

		CAF_ERROR = 100
	};


	type PeerStatus: enum {

		INITIALIZING,

		CONNECTING,

		CONNECTED,

		PEERED,

		DISCONNECTED,

		RECONNECTING,
	};

	type NetworkInfo: record {

		address: string &log;

		bound_port: port &log;
	};

	type EndpointInfo: record {

		id: string;

		network: NetworkInfo &optional;
	};

	type PeerInfo: record {
		peer: EndpointInfo;
		status: PeerStatus;



		is_outbound: bool;
	};

	type PeerInfos: vector of PeerInfo;


	type Data: record {
		data: opaque of Broker::Data &optional;
	};


	type DataVector: vector of Broker::Data;


	type Event: record {

		name: string &optional;

		args: DataVector;
	};



	type TableItem : record {
		key: Broker::Data;
		val: Broker::Data;
	};

















	global listen: function(a: string &default = default_listen_address,
	                        p: port &default = default_port,
	                        retry: interval &default = default_listen_retry): port;


















	global peer: function(a: string, p: port &default=default_port,
	                      retry: interval &default=default_connect_retry): bool;















	global unpeer: function(a: string, p: port): bool;









	global is_outbound_peering: function(a: string, p: port): bool;




	global peers: function(): vector of PeerInfo;




	global node_id: function(): string;





	global peering_stats: function(): table[string] of BrokerPeeringStats;



	global flush_logs: function(): count;









	global publish_id: function(topic: string, id: string): bool;










	global subscribe: function(topic_prefix: string): bool;









	global unsubscribe: function(topic_prefix: string): bool;













	global forward: function(topic_prefix: string): bool;
}

@load base/bif/comm.bif
@load base/bif/messaging.bif

module Broker;

event Broker::log_flush() &priority=10
	{
	Broker::flush_logs();
	schedule Broker::log_batch_interval { Broker::log_flush() };
	}

event zeek_init()
	{
	schedule Broker::log_batch_interval { Broker::log_flush() };
	}

event retry_listen(a: string, p: port, retry: interval)
	{
	listen(a, p, retry);
	}

function listen(a: string, p: port, retry: interval): port
	{
	local bound = __listen(a, p);

	if ( bound == 0/tcp )
		{
		local e = getenv("ZEEK_DEFAULT_LISTEN_RETRY");

		if ( e != "" )
			retry = (e as double) as interval;

		if ( retry != 0secs )
			schedule retry { retry_listen(a, p, retry) };
		}

	return bound;
	}

function peer(a: string, p: port, retry: interval): bool
	{
	return __peer(a, p, retry);
	}

function unpeer(a: string, p: port): bool
	{
	return __unpeer(a, p);
	}

function is_outbound_peering(a: string, p: port): bool
	{
	return __is_outbound_peering(a, p);
	}

function peers(): vector of PeerInfo
	{
	return __peers();
	}

function node_id(): string
	{
	return __node_id();
	}

function peering_stats(): table[string] of BrokerPeeringStats
	{
	return __peering_stats();
	}

function flush_logs(): count
	{
	return __flush_logs();
	}

function publish_id(topic: string, id: string): bool
	{
	return __publish_id(topic, id);
	}

function subscribe(topic_prefix: string): bool
	{
	return __subscribe(topic_prefix);
	}

function forward(topic_prefix: string): bool
	{
	return __forward(topic_prefix);
	}

function unsubscribe(topic_prefix: string): bool
	{
	return __unsubscribe(topic_prefix);
	}
