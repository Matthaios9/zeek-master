


module MQTT;

@load base/protocols/mqtt/consts

export {
	redef enum Log::ID += {
		CONNECT_LOG,
		SUBSCRIBE_LOG,
		PUBLISH_LOG,
	};


	const ports = { 1883/tcp } &redef;

	global log_policy_connect: Log::PolicyHook;
	global log_policy_subscribe: Log::PolicyHook;
	global log_policy_publish: Log::PolicyHook;

	type MQTT::SubUnsub: enum {
		MQTT::SUBSCRIBE,
		MQTT::UNSUBSCRIBE,
	} &redef;

	type ConnectInfo: record {

		ts:             time    &log;

		uid:            string  &log;

		id:             conn_id &log;


		proto_name:     string  &log &optional;

		proto_version:  string  &log &optional;

		client_id:      string  &log &optional;

		connect_status: string  &log &optional;


		will_topic:     string  &log &optional;

		will_payload:   string  &log &optional;
	};

	type SubscribeInfo: record {

		ts:                time     &log;

		uid:               string   &log;

		id:                conn_id  &log;


		action:            SubUnsub &log;

		topics:             string_vec   &log;

		qos_levels:         index_vec    &log &optional;

		granted_qos_level: count    &log &optional;

		ack:               bool     &log &default=F;
	};

	type PublishInfo: record {

		ts:          time    &log;

		uid:         string  &log;

		id:          conn_id &log;



		from_client: bool    &log;

		retain:      bool    &log;

		qos:         string  &log;



		status:      string  &log &default="incomplete_qos";


		topic:       string  &log;

		payload:     string  &log;




		payload_len: count   &log;


		ack:         bool    &default=F;

		rec:         bool    &default=F;

		rel:         bool    &default=F;

		comp:        bool    &default=F;

		qos_level:   count   &default=0;
	};



	global MQTT::log_mqtt: event(rec: ConnectInfo);



	global publish_expire: function(tbl: table[count] of PublishInfo, idx: count): interval;



	global subscribe_expire: function(tbl: table[count] of SubscribeInfo, idx: count): interval;


	type State: record {

		publish: table[count] of PublishInfo &optional &write_expire=5secs &expire_func=publish_expire;


		subscribe: table[count] of SubscribeInfo &optional &write_expire=5secs &expire_func=subscribe_expire;
	};
}

function publish_expire(tbl: table[count] of PublishInfo, idx: count): interval
	{
	Log::write(PUBLISH_LOG, tbl[idx]);
	return 0sec;
	}

function subscribe_expire(tbl: table[count] of SubscribeInfo, idx: count): interval
	{
	Log::write(SUBSCRIBE_LOG, tbl[idx]);
	return 0sec;
	}

redef record connection += {
	mqtt: ConnectInfo &optional;
	mqtt_state: State &optional;
};


event zeek_init() &priority=5
	{
	Log::create_stream(MQTT::CONNECT_LOG, Log::Stream($columns=ConnectInfo, $ev=log_mqtt, $path="mqtt_connect", $policy=log_policy_connect));
	Log::create_stream(MQTT::SUBSCRIBE_LOG, Log::Stream($columns=SubscribeInfo, $path="mqtt_subscribe", $policy=log_policy_subscribe));
	Log::create_stream(MQTT::PUBLISH_LOG, Log::Stream($columns=PublishInfo, $path="mqtt_publish", $policy=log_policy_publish));

	Analyzer::register_for_ports(Analyzer::ANALYZER_MQTT, ports);
	}

function set_session(c: connection): ConnectInfo
	{
	if ( ! c?$mqtt )
		c$mqtt = ConnectInfo($ts  = network_time(),
		                     $uid = c$uid,
		                     $id  = c$id);

	if ( ! c?$mqtt_state )
		{
		c$mqtt_state = State();
		c$mqtt_state$publish = table();
		c$mqtt_state$subscribe = table();
		}

	return c$mqtt;
	}

event mqtt_connect(c: connection, msg: MQTT::ConnectMsg) &priority=5
	{
	local info = set_session(c);

	info$proto_name = msg$protocol_name;
	info$proto_version = versions[msg$protocol_version];
	info$client_id = msg$client_id;
	if ( msg?$will_topic )
		info$will_topic = msg$will_topic;
	if ( msg?$will_msg )
		info$will_payload = msg$will_msg;
	}

event mqtt_connack(c: connection, msg: MQTT::ConnectAckMsg) &priority=5
	{
	local info = set_session(c);

	info$connect_status = return_codes[msg$return_code];

	Log::write(CONNECT_LOG, info);
	}

event mqtt_publish(c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg) &priority=5
	{
	set_session(c);

	local pi = PublishInfo($ts=network_time(),
	                       $uid=c$uid,
	                       $id=c$id,
	                       $from_client=is_orig,
	                       $retain=msg$retain,
	                       $qos=qos_levels[msg$qos],
	                       $qos_level=msg$qos,
	                       $topic=msg$topic,
	                       $payload=msg$payload,
	                       $payload_len=msg$payload_len);
	if ( pi$qos_level == 0 )
		pi$status="ok";

	c$mqtt_state$publish[msg_id] = pi;
	}

event mqtt_publish(c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg) &priority=-5
	{
	local pi = c$mqtt_state$publish[msg_id];

	if ( pi$qos_level == 0 )
		{
		Log::write(PUBLISH_LOG, pi);
		delete c$mqtt_state$publish[msg_id];
		}
	}

event mqtt_puback(c: connection, is_orig: bool, msg_id: count) &priority=5
	{
	set_session(c);

	if ( msg_id in c$mqtt_state$publish )
		{
		local pi = c$mqtt_state$publish[msg_id];
		pi$ack = T;
		if ( pi$qos_level == 1 )
			pi$status = "ok";
		}
	}

event mqtt_puback(c: connection, is_orig: bool, msg_id: count) &priority=-5
	{
	if ( msg_id in c$mqtt_state$publish )
		{
		local pi = c$mqtt_state$publish[msg_id];

		if ( pi$status == "ok" )
			{
			Log::write(PUBLISH_LOG, pi);
			delete c$mqtt_state$publish[msg_id];
			}
		}
	}

event mqtt_pubrec(c: connection, is_orig: bool, msg_id: count) &priority=5
	{
	set_session(c);

	if ( msg_id in c$mqtt_state$publish )
		{
		local pi = c$mqtt_state$publish[msg_id];
		pi$rec = T;
		}
	}

event mqtt_pubrel(c: connection, is_orig: bool, msg_id: count) &priority=5
	{
	set_session(c);

	if ( msg_id in c$mqtt_state$publish )
		{
		local pi = c$mqtt_state$publish[msg_id];
		pi$rel = T;
		}
	}

event mqtt_pubcomp(c: connection, is_orig: bool, msg_id: count) &priority=5
	{
	set_session(c);
	if ( msg_id !in c$mqtt_state$publish )
		return;

	local pi = c$mqtt_state$publish[msg_id];
	pi$comp = T;

	if ( pi$qos_level == 2 && pi$rec && pi$rel && pi$comp )
		pi$status = "ok";
	}

event mqtt_pubcomp(c: connection, is_orig: bool, msg_id: count) &priority=-5
	{
	if ( msg_id !in c$mqtt_state$publish )
		return;

	local pi = c$mqtt_state$publish[msg_id];
	if ( pi$status == "ok" )
		{
		Log::write(PUBLISH_LOG, pi);
		delete c$mqtt_state$publish[msg_id];
		}
	}


event mqtt_subscribe(c: connection, msg_id: count, topics: string_vec, requested_qos: index_vec) &priority=5
	{
	set_session(c);

	local si = SubscribeInfo($ts  = network_time(),
	                         $uid = c$uid,
	                         $id  = c$id,
	                         $action = MQTT::SUBSCRIBE,
	                         $topics = topics,
	                         $qos_levels = requested_qos);

	c$mqtt_state$subscribe[msg_id] = si;
	}

event mqtt_suback(c: connection, msg_id: count, granted_qos: count) &priority=5
	{
	set_session(c);

	if ( msg_id !in c$mqtt_state$subscribe )
		return;

	local x = c$mqtt_state$subscribe[msg_id];
	x$granted_qos_level = granted_qos;
	x$ack = T;

	Log::write(MQTT::SUBSCRIBE_LOG, x);
	delete c$mqtt_state$subscribe[msg_id];
	}

event mqtt_unsubscribe(c: connection, msg_id: count, topics: string_vec) &priority=5
	{
	set_session(c);

	local si = SubscribeInfo($ts  = network_time(),
	                         $uid = c$uid,
	                         $id  = c$id,
	                         $action = MQTT::UNSUBSCRIBE,
	                         $topics = topics);

	c$mqtt_state$subscribe[msg_id] = si;
	}

event mqtt_unsuback(c: connection, msg_id: count) &priority=-5
	{
	set_session(c);

	if ( msg_id !in c$mqtt_state$subscribe )
		return;

	local x = c$mqtt_state$subscribe[msg_id];
	x$ack = T;

	Log::write(MQTT::SUBSCRIBE_LOG, x);
	delete c$mqtt_state$subscribe[msg_id];
	}
