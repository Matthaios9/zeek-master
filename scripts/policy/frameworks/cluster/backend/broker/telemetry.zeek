

@load base/frameworks/telemetry

module Cluster;




global broker_peer_buffer_messages_gf = Telemetry::register_gauge_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="broker-peer-buffer-messages",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Number of messages queued in Broker's send buffers",
));









global broker_peer_buffer_recent_max_messages_gf = Telemetry::register_gauge_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="broker-peer-buffer-recent-max-messages",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Maximum number of messages recently queued in Broker's send buffers",
));






global broker_peer_buffer_overflows_cf = Telemetry::register_counter_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="broker-peer-buffer-overflows",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Number of overflows in Broker's send buffers",
));





type EpochData: record {
	peer_id: string;
	num_overflows: count &default=0;
	num_past_overflows: count &default=0;
};


global peering_epoch_data: table[string] of EpochData;

hook Telemetry::sync()
	{
	local peers = Broker::peering_stats();
	local nn: NamedNode;
	local labels: vector of string;
	local ed: EpochData;

	for ( peer_id, stats in peers )
		{



		nn = nodeid_to_node(peer_id);

		if ( |nn$name| == 0 )
			next;

		labels = vector(nn$name);

		Telemetry::gauge_family_set(broker_peer_buffer_messages_gf,
		    labels, stats$num_queued);
		Telemetry::gauge_family_set(broker_peer_buffer_recent_max_messages_gf,
		    labels, stats$max_queued_recently);

		if ( nn$name !in peering_epoch_data )
			peering_epoch_data[nn$name] = EpochData($peer_id=peer_id);

		ed = peering_epoch_data[nn$name];

		if ( peer_id != ed$peer_id )
			{




			ed$peer_id = peer_id;
			ed$num_past_overflows += ed$num_overflows;
			}

		ed$num_overflows = stats$num_overflows;

		Telemetry::counter_family_set(broker_peer_buffer_overflows_cf,
		    labels, ed$num_past_overflows + ed$num_overflows);
		}
	}
