










@load ./main
@load base/utils/files
@load base/frameworks/cluster
@load base/protocols/conn/removal-hooks

module IRC;

export {
	redef record Info += {

		dcc_file_name:         string &log &optional;

		dcc_file_size:         count  &log &optional;

		dcc_mime_type:         string &log &optional;
	};



	global finalize_irc_data: Conn::RemovalHook;
}

global dcc_expected_transfers: table[addr, port] of Info &read_expire=5mins;

function dcc_relay_topic(): string &is_used
	{
	local rval = Cluster::rr_topic(Cluster::proxy_pool, "dcc_transfer_rr_key");

	if ( rval == "" )

		return Cluster::manager_topic;

	return rval;
	}

event dcc_transfer_add(host: addr, p: port, info: Info) &is_used
	{
@if ( Cluster::local_node_type() == Cluster::PROXY ||
      Cluster::local_node_type() == Cluster::MANAGER )
	Cluster::publish(Cluster::worker_topic, dcc_transfer_add, host, p, info);
@else
	dcc_expected_transfers[host, p] = info;
	Analyzer::schedule_analyzer(0.0.0.0, host, p,
	                            Analyzer::ANALYZER_IRC_DATA, 5 min);
@endif
	}

event dcc_transfer_remove(host: addr, p: port) &is_used
	{
@if ( Cluster::local_node_type() == Cluster::PROXY ||
      Cluster::local_node_type() == Cluster::MANAGER )
	Cluster::publish(Cluster::worker_topic, dcc_transfer_remove, host, p);
@else
	delete dcc_expected_transfers[host, p];
@endif
	}

function log_dcc(f: fa_file)
	{
	if ( ! f?$conns ) return;

	for ( cid, c in f$conns )
		{
		if ( [cid$resp_h, cid$resp_p] !in dcc_expected_transfers ) next;

		local irc = dcc_expected_transfers[cid$resp_h, cid$resp_p];

		local tmp = irc$command;
		irc$command = "DCC";
		Log::write(IRC::LOG, irc);
		irc$command = tmp;



		delete irc$dcc_file_name;
		delete irc$dcc_file_size;
		delete irc$dcc_mime_type;

		delete dcc_expected_transfers[cid$resp_h, cid$resp_p];

@if ( Cluster::is_enabled() )
		Cluster::publish(dcc_relay_topic(), dcc_transfer_remove,
		                 cid$resp_h, cid$resp_p);
@endif
		return;
		}
	}

event file_sniff(f: fa_file, meta: fa_metadata) &priority=-5
	{
	if ( f$source == "IRC_DATA" )
		log_dcc(f);
	}

event irc_dcc_message(c: connection, is_orig: bool,
			prefix: string, target: string,
			dcc_type: string, argument: string,
			address: addr, dest_port: count, size: count) &priority=5
	{
	set_session(c);
	if ( dcc_type != "SEND" )
		return;
	c$irc$dcc_file_name = argument;
	c$irc$dcc_file_size = size;
	local p = count_to_port(dest_port, tcp);
	Analyzer::schedule_analyzer(0.0.0.0, address, p, Analyzer::ANALYZER_IRC_DATA, 5 min);
	dcc_expected_transfers[address, p] = c$irc;

@if ( Cluster::is_enabled() )
	Cluster::publish(dcc_relay_topic(), dcc_transfer_add, address, p, c$irc);
@endif
	}

event scheduled_analyzer_applied(c: connection, a: Analyzer::Tag) &priority=10
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in dcc_expected_transfers )
		{
		add c$service["irc-dcc-data"];
		Conn::register_removal_hook(c, finalize_irc_data);
		}
	}

hook finalize_irc_data(c: connection)
	{
	if ( [c$id$resp_h, c$id$resp_p] in dcc_expected_transfers )
		{
		delete dcc_expected_transfers[c$id$resp_h, c$id$resp_p];

@if ( Cluster::is_enabled() )
		Cluster::publish(dcc_relay_topic(), dcc_transfer_remove,
		                 c$id$resp_h, c$id$resp_p);
@endif
		}
	}
