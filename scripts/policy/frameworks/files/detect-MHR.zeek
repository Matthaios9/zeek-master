


@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

module TeamCymruMalwareHashRegistry;

export {
	redef enum Notice::Type += {


		Match
	};


	option match_file_types = /application\/x-dosexec/ |
	                         /application\/vnd\.ms-cab-compressed/ |
	                         /application\/pdf/ |
	                         /application\/x-shockwave-flash/ |
	                         /application\/x-java-applet/ |
	                         /application\/jar/ |
	                         /video\/mp4/;




	option match_sub_url = "https://www.virustotal.com/gui/search/%s";





	option notice_threshold = 10;
}

function do_mhr_lookup(hash: string, fi: Notice::FileInfo)
	{
	local hash_domain = fmt("%s.malware.hash.cymru.com", hash);

	when [hash, fi, hash_domain] ( local MHR_result = lookup_hostname_txt(hash_domain) )
		{

		local MHR_answer = split_string1(MHR_result, / /);

		if ( |MHR_answer| == 2 )
			{
			local mhr_detect_rate = MHR_answer[1] as count;

			if ( mhr_detect_rate >= notice_threshold )
				{
				local mhr_first_detected = (MHR_answer[0] as double) as time;
				local readable_first_detected = strftime("%Y-%m-%d %H:%M:%S", mhr_first_detected);
				local message = fmt("Malware Hash Registry Detection rate: %d%%  Last seen: %s", mhr_detect_rate, readable_first_detected);
				local virustotal_url = fmt(match_sub_url, hash);


				local n: Notice::Info = Notice::Info($note=Match, $msg=message, $sub=virustotal_url);
				Notice::populate_file_info2(fi, n);
				NOTICE(n);
				}
			}
		}
	}

event file_hash(f: fa_file, kind: string, hash: string)
	{
	if ( kind == "sha1" && f?$info && f$info?$mime_type &&
	     match_file_types in f$info$mime_type )
		do_mhr_lookup(hash, Notice::create_file_info(f));
	}
