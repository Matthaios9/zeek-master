

@load base/misc/installation
@load policy/frameworks/management



@load policy/frameworks/management/controller/config

module Management::Agent;

export {




	const name = getenv("ZEEK_AGENT_NAME") &redef;








	const stdout_file = "stdout" &redef;



	const stderr_file = "stderr" &redef;







	const listen_address = getenv("ZEEK_AGENT_ADDR") &redef;




	const listen_port = getenv("ZEEK_AGENT_PORT") &redef;


	const default_port = 2151/tcp &redef;



	const archive_logs = T &redef;



	const archive_interval = 0 sec &redef;








	const archive_cmd = "" &redef;


	const archive_dir = Installation::log_dir &redef;



	const topic_prefix = "zeek/management/agent" &redef;








	const controller = Broker::NetworkInfo($address="127.0.0.1",
	    $bound_port=Management::Controller::network_info()$bound_port) &redef;






	const directory = "" &redef;


	global get_name: function(): string;



	global instance: function(): Management::Instance;




	global endpoint_info: function(): Broker::EndpointInfo;
}

function get_name(): string
	{
	if ( name != "" )
		return name;

	return fmt("agent-%s", gethostname());
	}

function instance(): Management::Instance
	{
	local epi = endpoint_info();
	return Management::Instance($name=epi$id,
	    $host=epi$network$address as addr,
	    $listen_port=epi$network$bound_port);
	}

function endpoint_info(): Broker::EndpointInfo
	{
	local epi: Broker::EndpointInfo;
	local network: Broker::NetworkInfo;

	epi$id = get_name();

	if ( Management::Agent::listen_address != "" )
		network$address = Management::Agent::listen_address;
	else if ( Management::default_address != "" )
		network$address = Management::default_address;
	else
		network$address = "0.0.0.0";

	if ( Management::Agent::listen_port != "" )
		network$bound_port = to_port(Management::Agent::listen_port);
	else
		network$bound_port = Management::Agent::default_port;

	epi$network = network;

	return epi;
	}
