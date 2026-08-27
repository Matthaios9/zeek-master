

@load ./types

module NetControl;

export {



	type PluginState: record {

		config: table[string] of string &default=table();


		_id: count &optional;


		_priority: int &default=+0;


		_activated: bool &default=F;
	};














	type Plugin: record {


		name: function(state: PluginState) : string;



		can_expire: bool;








		init: function(state: PluginState) &optional;



		done: function(state: PluginState) &optional;





		add_rule: function(state: PluginState, r: Rule) : bool &optional;






		remove_rule: function(state: PluginState, r: Rule, reason: string) : bool &optional;
	};






	redef record PluginState += {


		plugin: Plugin &optional;
	};

}
