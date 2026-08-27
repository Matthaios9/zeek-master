





@load base/utils/paths

@load ./config




redef SupervisorControl::enable_listen = T;




redef Broker::default_listen_address = "127.0.0.1";

event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local epi = Management::Agent::endpoint_info();
	local sn = Supervisor::NodeConfig($name=epi$id, $bare_mode=T,
		$addl_base_scripts=vector("policy/frameworks/management/agent/main.zeek"));




	local statedir = build_path(Management::get_state_dir(), "nodes");

	if ( ! mkdir(statedir) )
		print(fmt("warning: could not create state dir '%s'", statedir));

	if ( Management::Agent::directory != "" )
		sn$directory = build_path(statedir, Management::Agent::directory);
	else
		sn$directory = build_path(statedir, Management::Agent::get_name());

	if ( ! mkdir(sn$directory) )
		print(fmt("warning: could not create agent state dir '%s'", sn$directory));






	if ( getenv("OS") == "Windows_NT" )
		{
		sn$stdout_file = Management::Agent::stdout_file;
		sn$stderr_file = Management::Agent::stderr_file;
		}


	sn$env["ZEEK_MANAGEMENT_NODE"] = "AGENT";

	local res = Supervisor::create(sn);

	if ( res != "" )
		{
		print(fmt("error: supervisor could not create agent node: %s", res));
		exit(1);
		}
	}
