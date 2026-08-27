




@load base/frameworks/sumstats
@load base/frameworks/signatures
@load-sigs ./detect-low-ttls.sig

redef Signatures::ignored_ids += /traceroute-detector.*/;

module Traceroute;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	redef enum Notice::Type += {



		Detected
	};






	const require_low_ttl_packets = T &redef;




	const icmp_time_exceeded_threshold: double = 3 &redef;




	const icmp_time_exceeded_interval = 3min &redef;


	type Info: record {

		ts:    time &log;

		src:   addr &log;

		dst:   addr &log;

		proto: string &log;
	};

	global log_traceroute: event(rec: Traceroute::Info);
}

event zeek_init() &priority=5
	{
	Log::create_stream(Traceroute::LOG, Log::Stream($columns=Info, $ev=log_traceroute, $path="traceroute", $policy=log_policy));

	local r1 = SumStats::Reducer($stream="traceroute.time_exceeded", $apply=set(SumStats::UNIQUE));
	local r2 = SumStats::Reducer($stream="traceroute.low_ttl_packet", $apply=set(SumStats::SUM));
	SumStats::create(SumStats::SumStat($name="traceroute-detection",
		$epoch=icmp_time_exceeded_interval,
		$reducers=set(r1, r2),
		$threshold_val(key: SumStats::Key, result: SumStats::Result) =
			{


			if ( require_low_ttl_packets && result["traceroute.low_ttl_packet"]$sum == 0 )
				return 0.0;
			else
				return result["traceroute.time_exceeded"]$unique+0;
			},
		$threshold=icmp_time_exceeded_threshold,
		$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
			{
			local parts = split_string_n(key$str, /-/, F, 2);
			local src = parts[0] as addr;
			local dst = parts[1] as addr;
			local proto = parts[2];
			Log::write(LOG, Info($ts=network_time(), $src=src, $dst=dst, $proto=proto));
			NOTICE(Notice::Info($note=Traceroute::Detected,
			                    $msg=fmt("%s seems to be running traceroute using %s", src, proto),
			                    $src=src,
			                    $identifier=cat(src,proto)));
			}));
	}


event signature_match(state: signature_state, msg: string, data: string)
	{
	if ( state$sig_id == /traceroute-detector.*/ )
		{
		SumStats::observe("traceroute.low_ttl_packet", SumStats::Key($str=cat(state$conn$id$orig_h,"-", state$conn$id$resp_h, "-", get_port_transport_proto(state$conn$id$resp_p))), SumStats::Observation($num=1));
		}
	}

event icmp_time_exceeded(c: connection, info: icmp_info, code: count, context: icmp_context)
	{
	SumStats::observe("traceroute.time_exceeded", SumStats::Key($str=cat(context$id$orig_h,"-", context$id$resp_h, "-", get_port_transport_proto(context$id$resp_p))), SumStats::Observation($str=cat(c$id$orig_h)));
	}
