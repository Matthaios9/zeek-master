

module OpenFlow;

@load ./consts

export {

	type Plugin: enum {

		INVALID,
	};




	type ControllerState: record {

		_plugin: Plugin &optional;

		_name: string &optional;

		_activated: bool &default=F;
	} &redef;






	type ofp_match: record {

		in_port: count &optional;

		dl_src: string &optional;

		dl_dst: string &optional;

		dl_vlan: count &optional;

		dl_vlan_pcp: count &optional;

		dl_type: count &optional;

		nw_tos: count &optional;

		nw_proto: count &optional;



		nw_src: subnet &optional;

		nw_dst: subnet &optional;

		tp_src: count &optional;

		tp_dst: count &optional;
	} &log;



	type ofp_flow_action: record {

		out_ports: vector of count &default=vector();

		vlan_vid: count &optional;

		vlan_pcp: count &optional;

		vlan_strip: bool &default=F;

		dl_src: string &optional;

		dl_dst: string &optional;

		nw_tos: count &optional;

		nw_src: addr &optional;

		nw_dst: addr &optional;

		tp_src: count &optional;

		tp_dst: count &optional;
	} &log;


	type ofp_flow_mod: record {



		cookie: count;



		table_id: count &optional;

		command: ofp_flow_mod_command;

		idle_timeout: count &default=0;

		hard_timeout: count &default=0;

		priority: count &default=0;


		out_port: count &optional;
		out_group: count &optional;

		flags: count &default=0;

		actions: ofp_flow_action &default=ofp_flow_action();
	} &log;


	type Controller: record {

		state: ControllerState;

		supports_flow_removed: bool;

		describe: function(state: ControllerState): string;

		init: function (state: ControllerState) &optional;

		destroy: function (state: ControllerState) &optional;

		flow_mod: function(state: ControllerState, match: ofp_match, flow_mod: ofp_flow_mod): bool &optional;

		flow_clear: function(state: ControllerState): bool &optional;
	};
}
