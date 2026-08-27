


@load base/protocols/ssh
@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/frameworks/intel

module SSH;

export {
	redef enum Notice::Type += {



		Password_Guessing,



		Login_By_Password_Guesser,
	};

	redef enum Intel::Where += {

		SSH::SUCCESSFUL_LOGIN,
	};



	const password_guesses_limit: double = 30 &redef;



	const guessing_timeout = 30 mins &redef;




	const ignore_guessers: table[subnet] of subnet &redef;
}

event zeek_init()
	{
	local r1 = SumStats::Reducer($stream="ssh.login.failure", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=5);
	SumStats::create(SumStats::SumStat(
		$name="detect-ssh-bruteforcing",
		$epoch=guessing_timeout,
		$reducers=set(r1),
		$threshold_val(key: SumStats::Key, result: SumStats::Result) =
			{
			return result["ssh.login.failure"]$sum;
			},
		$threshold=password_guesses_limit,
		$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
			{
			local r = result["ssh.login.failure"];
			local sub_msg = fmt("Sampled servers: ");
			local samples = r$samples;
			for ( i in samples )
				{
				if ( samples[i]?$str )
					sub_msg = fmt("%s%s %s", sub_msg, i==0 ? "":",", samples[i]$str);
				}

			NOTICE(Notice::Info($note=Password_Guessing,
			                    $msg=fmt("%s appears to be guessing SSH passwords (seen in %d connections).", key$host, r$num),
			                    $sub=sub_msg,
			                    $src=key$host,
			                    $identifier=cat(key$host)));
			}));
	}

event ssh_auth_successful(c: connection, auth_method_none: bool)
	{
	local id = c$id;

	Intel::seen(Intel::Seen($host=id$orig_h,
	                        $conn=c,
	                        $where=SSH::SUCCESSFUL_LOGIN));
	}

event ssh_auth_failed(c: connection)
	{
	local id = c$id;



	if ( ! (id$orig_h in ignore_guessers &&
	        id$resp_h in ignore_guessers[id$orig_h]) )
		SumStats::observe("ssh.login.failure", SumStats::Key($host=id$orig_h), SumStats::Observation($str=cat(id$resp_h)));
	}
