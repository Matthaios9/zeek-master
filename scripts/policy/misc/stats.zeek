

@load base/frameworks/notice
@load base/frameworks/telemetry
@load base/utils/time

module Stats;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;


	option report_interval = 5min;

	type Info: record {

		ts:            time      &log;

		peer:          string    &log;

		mem:           count     &log;

		pkts_proc:     count     &log;


		bytes_recv:    count     &log;



		pkts_dropped:  count     &log &optional;


		pkts_link:     count     &log &optional;


		pkt_lag:       interval  &log &optional;


		pkts_filtered: count     &log &optional;


		events_proc:   count     &log;


		events_queued: count     &log;


		active_tcp_conns: count  &log;

		active_udp_conns: count &log;

		active_icmp_conns: count &log;


		tcp_conns:        count  &log;

		udp_conns:        count &log;

		icmp_conns:        count &log;


		timers: count &log;

		active_timers: count &log;


		files: count &log;

		active_files: count &log;


		dns_requests: count &log;

		active_dns_requests: count &log;


		reassem_tcp_size: count &log;

		reassem_file_size: count &log;

		reassem_frag_size: count &log;

		reassem_unknown_size: count &log;
	};


	global log_stats: event(rec: Info);
}

global bytes_received_cf = Telemetry::register_counter_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="net-received-bytes",
    $unit="",
    $help_text="Total number of bytes received",
));

global packets_received_cf = Telemetry::register_counter_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="net-received-packets",
    $unit="",
    $help_text="Total number of packets received",
));

global packets_dropped_cf = Telemetry::register_counter_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="net-dropped-packets",
    $unit="",
    $help_text="Total number of packets dropped",
));

global link_packets_cf = Telemetry::register_counter_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="net-link-packets",
    $unit="",
    $help_text="Total number of packets on the packet source link before filtering",
));

global packets_filtered_cf = Telemetry::register_counter_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="net-filtered-packets",
    $unit="",
    $help_text="Total number of packets filtered",
));

global packet_lag_gf = Telemetry::register_gauge_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="net-packet-lag",
    $unit="seconds",
    $help_text="Difference of network time and wallclock time in seconds.",
));



global network_time_cf = Telemetry::register_gauge_family(Telemetry::MetricOpts(
    $prefix="zeek",
    $name="net-timestamp",
    $unit="seconds",
    $help_text="The current network time.",
));

global no_labels: vector of string;

hook Telemetry::sync()
	{
	Telemetry::gauge_family_set(network_time_cf, no_labels, network_time() as double);
	local net_stats = get_net_stats();
	Telemetry::counter_family_set(bytes_received_cf, no_labels, net_stats$bytes_recvd);
	Telemetry::counter_family_set(packets_received_cf, no_labels, net_stats$pkts_recvd);

	if ( reading_live_traffic() )
		{
		Telemetry::counter_family_set(packets_dropped_cf, no_labels, net_stats$pkts_dropped);
		Telemetry::counter_family_set(link_packets_cf, no_labels, net_stats$pkts_link);

		if ( net_stats?$pkts_filtered )
			Telemetry::counter_family_set(packets_filtered_cf, no_labels, net_stats$pkts_filtered);

		Telemetry::gauge_family_set(packet_lag_gf, no_labels,
		                            (current_time() - network_time()) as double);
		}
	}

event zeek_init() &priority=5
	{
	Log::create_stream(Stats::LOG, Log::Stream($columns=Info, $ev=log_stats, $path="stats", $policy=log_policy));
	}

event check_stats(then: time, last_ns: NetStats, last_cs: ConnStats, last_ps: ProcStats, last_es: EventStats, last_rs: ReassemblerStats, last_ts: TimerStats, last_fs: FileAnalysisStats, last_ds: DNSStats)
	{
	local nettime = network_time();
	local ns = get_net_stats();
	local cs = get_conn_stats();
	local ps = get_proc_stats();
	local es = get_event_stats();
	local rs = get_reassembler_stats();
	local ts = get_timer_stats();
	local fs = get_file_analysis_stats();
	local ds = get_dns_stats();

	local info = Info($ts=nettime,
	                  $peer=peer_description,
	                  $mem=ps$mem/1048576,
	                  $pkts_proc=ns$pkts_recvd - last_ns$pkts_recvd,
	                  $bytes_recv = ns$bytes_recvd  - last_ns$bytes_recvd,

	                  $active_tcp_conns=cs$num_tcp_conns,
	                  $tcp_conns=cs$cumulative_tcp_conns - last_cs$cumulative_tcp_conns,
	                  $active_udp_conns=cs$num_udp_conns,
	                  $udp_conns=cs$cumulative_udp_conns - last_cs$cumulative_udp_conns,
	                  $active_icmp_conns=cs$num_icmp_conns,
	                  $icmp_conns=cs$cumulative_icmp_conns - last_cs$cumulative_icmp_conns,

	                  $reassem_tcp_size=rs$tcp_size,
	                  $reassem_file_size=rs$file_size,
	                  $reassem_frag_size=rs$frag_size,
	                  $reassem_unknown_size=rs$unknown_size,

	                  $events_proc=es$dispatched - last_es$dispatched,
	                  $events_queued=es$queued - last_es$queued,

	                  $timers=ts$cumulative - last_ts$cumulative,
	                  $active_timers=ts$current,

	                  $files=fs$cumulative - last_fs$cumulative,
	                  $active_files=fs$current,

	                  $dns_requests=ds$requests - last_ds$requests,
	                  $active_dns_requests=ds$pending);




	if ( reading_live_traffic() )
		{
		info$pkt_lag = get_packet_lag();
		info$pkts_dropped = ns$pkts_dropped  - last_ns$pkts_dropped;
		info$pkts_link = ns$pkts_link  - last_ns$pkts_link;



		if ( ns?$pkts_filtered )
			info$pkts_filtered = ns$pkts_filtered - last_ns$pkts_filtered;
		}

	Log::write(Stats::LOG, info);

	if ( zeek_is_terminating() )


		return;

	schedule report_interval { check_stats(nettime, ns, cs, ps, es, rs, ts, fs, ds) };
	}

event zeek_init()
	{
	schedule report_interval { check_stats(network_time(), get_net_stats(), get_conn_stats(), get_proc_stats(), get_event_stats(), get_reassembler_stats(), get_timer_stats(), get_file_analysis_stats(), get_dns_stats()) };
	}
