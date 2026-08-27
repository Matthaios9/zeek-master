



function duration_to_mins_secs(dur: interval): string
	{
	local dur_count = (dur as double) as count;
	return fmt("%dm%ds", dur_count/60, dur_count%60);
	}


const null_ts = 0 as time;




function get_packet_lag(): interval
	{




	local pkt_ts = get_current_packet_ts();
	if (pkt_ts == null_ts)
		return 0 sec;

	return current_time() - pkt_ts;
	}
