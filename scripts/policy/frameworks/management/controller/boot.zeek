






@load base/utils/paths

@load ./config

event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local epi = Management::Controller::endpoint_info();
	local sn = Supervisor::NodeConfig($name=epi$id, $bare_mode=T,
	    $addl_base_scripts=vector("policy/frameworks/management/controller/main.zeek"));




	local statedir = build_path(Management::get_state_dir(), "nodes");

	if ( ! mkdir(statedir) )
		print(fmt("warning: could not create state dir '%s'", statedir));

	if ( Management::Controller::directory != "" )
		sn$directory = build_path(statedir, Management::Controller::directory);
	else
		sn$directory = build_path(statedir, Management::Controller::get_name());

	if ( ! mkdir(sn$directory) )
		print(fmt("warning: could not create controller state dir '%s'", sn$directory));






	if ( getenv("OS") == "Windows_NT" )
		{
		sn$stdout_file = Management::Controller::stdout_file;
		sn$stderr_file = Management::Controller::stderr_file;
		}


	sn$env["ZEEK_MANAGEMENT_NODE"] = "CONTROLLER";

	local res = Supervisor::create(sn);

	if ( res != "" )
		{
		print(fmt("error: supervisor could not create controller node: %s", res));
		exit(1);
		}
	}
