






module GLOBAL;

export {
	type TrackCount: record {

		n:     count &default=0;



		index: count &default=0;
	};



	const default_notice_thresholds: vector of count = {
		30, 100, 1000, 10000, 100000, 1000000, 10000000,
	} &redef;










	global check_threshold: function(v: vector of count, tracker: TrackCount): bool;




	global default_check_threshold: function(tracker: TrackCount): bool;
}

function new_track_count(): TrackCount
	{
	local tc: TrackCount;
	return tc;
	}

function check_threshold(v: vector of count, tracker: TrackCount): bool
	{
	if ( tracker$index < |v| && tracker$n >= v[tracker$index] )
		{
		++tracker$index;
		return T;
		}
	return F;
	}

function default_check_threshold(tracker: TrackCount): bool
	{
	return check_threshold(default_notice_thresholds, tracker);
	}
