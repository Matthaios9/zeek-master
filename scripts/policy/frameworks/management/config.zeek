






@load base/misc/installation


@load frameworks/cluster/backend/broker

@load ./types

module Management;

export {



	const role = Management::NONE &redef;




	const default_address = "0.0.0.0" &redef;



	const connect_retry = 1sec &redef;





	const spool_dir = getenv("ZEEK_MANAGEMENT_SPOOL_DIR") &redef;




	const state_dir = getenv("ZEEK_MANAGEMENT_STATE_DIR") &redef;




	global get_spool_dir: function(): string;




	global get_state_dir: function(): string;
}

function get_spool_dir(): string
	{
	if ( spool_dir != "" )
		return spool_dir;

	return Installation::spool_dir;
	}

function get_state_dir(): string
	{
	if ( state_dir != "" )
		return state_dir;

	return Installation::state_dir;
	}
