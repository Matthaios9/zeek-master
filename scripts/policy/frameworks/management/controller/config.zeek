

@load policy/frameworks/management

module Management::Controller;

export {




	const name = getenv("ZEEK_CONTROLLER_NAME") &redef;








	const stdout_file = "stdout" &redef;



	const stderr_file = "stderr" &redef;





	const listen_address = getenv("ZEEK_CONTROLLER_ADDR") &redef;





	const listen_port = getenv("ZEEK_CONTROLLER_PORT") &redef;






	const default_port = 2150/tcp &redef;






	const listen_address_websocket = getenv("ZEEK_CONTROLLER_WEBSOCKET_ADDR") &redef;





	const listen_port_websocket = getenv("ZEEK_CONTROLLER_WEBSOCKET_PORT") &redef;




	const default_port_websocket = 2149/tcp &redef;







	const tls_options_websocket = Cluster::WebSocketTLSOptions() &redef;




	const auto_assign_broker_ports = T &redef;




	const auto_assign_broker_start_port = 2200/tcp &redef;




	const auto_assign_metrics_ports = T &redef;




	const auto_assign_metrics_start_port = 9000/tcp &redef;


	const topic = "zeek/management/controller" &redef;





	const directory = "" &redef;



	const store_name = "controller";


	global get_name: function(): string;



	global network_info: function(): Broker::NetworkInfo;



	global network_info_websocket: function(): Broker::NetworkInfo;



	global endpoint_info: function(): Broker::EndpointInfo;



	global endpoint_info_websocket: function(): Broker::EndpointInfo;
}

function get_name(): string
	{
	if ( name != "" )
		return name;

	return fmt("controller-%s", gethostname());
	}

function network_info(): Broker::NetworkInfo
	{
	local ni: Broker::NetworkInfo;

	if ( Management::Controller::listen_address != "" )
		ni$address = Management::Controller::listen_address;
	else if ( Management::default_address != "" )
		ni$address = Management::default_address;
	else
		ni$address = "0.0.0.0";

	if ( Management::Controller::listen_port != "" )
		ni$bound_port = to_port(Management::Controller::listen_port);
	else
		ni$bound_port = Management::Controller::default_port;

	return ni;
	}

function network_info_websocket(): Broker::NetworkInfo
	{
	local ni: Broker::NetworkInfo;

	if ( Management::Controller::listen_address_websocket != "" )
		ni$address = Management::Controller::listen_address_websocket;
	else if ( Management::default_address != "" )
		ni$address = Management::default_address;
	else
		ni$address = "0.0.0.0";

	if ( Management::Controller::listen_port_websocket != "" )
		ni$bound_port = to_port(Management::Controller::listen_port_websocket);
	else
		ni$bound_port = Management::Controller::default_port_websocket;

	return ni;
	}

function endpoint_info(): Broker::EndpointInfo
	{
	local epi: Broker::EndpointInfo;

	epi$id = Management::Controller::get_name();
	epi$network = network_info();

	return epi;
	}

function endpoint_info_websocket(): Broker::EndpointInfo
	{
	local epi: Broker::EndpointInfo;

	epi$id = Management::Controller::get_name();
	epi$network = network_info_websocket();

	return epi;
	}
