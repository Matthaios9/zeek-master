

@load ./main
@load base/frameworks/cluster

module Config;

export {






	const config_files: set[string] = {} &redef;



	global read_config: function(filename: string);
}

global current_config: table[string] of string = table();

type ConfigItem: record {
	option_nv: string;
};

type EventFields: record {
	option_name: string;
	option_val: string;
};

event config_line(description: Input::EventDescription, tpe: Input::Event, p: EventFields)
	{
	}

event zeek_init() &priority=5
	{
	if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
		return;

	for ( fi in config_files )
		Input::add_table(Input::TableDescription($reader=Input::READER_CONFIG,
			$mode=Input::REREAD,
			$source=fi,
			$name=cat("config-", fi),
			$idx=ConfigItem,
			$val=ConfigItem,
			$want_record=F,
			$destination=current_config));
	}

event InputConfig::new_value(name: string, source: string, id: string, value: any)
	{
	if ( sub_bytes(name, 1,  15) != "config-oneshot-" && source !in config_files )
		return;

	Config::set_value(id, value, source);
	}

function read_config(filename: string)
	{


	if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
		return;

	local iname = cat("config-oneshot-", filename);

	Input::add_event(Input::EventDescription($reader=Input::READER_CONFIG,
		$mode=Input::MANUAL,
		$source=filename,
		$name=iname,
		$fields=EventFields,
		$ev=config_line));
	Input::remove(iname);
	}
