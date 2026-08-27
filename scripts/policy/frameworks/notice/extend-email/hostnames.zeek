




@load base/frameworks/notice/main

module Notice;





global tmp_notice_storage: table[string] of Notice::Info &create_expire=max_email_delay+10secs;


hook notice(n: Notice::Info) &priority=-1
	{
	if ( ! n?$src && ! n?$dst )
		return;


	if ( |n$email_dest| == 0 )
		return;




	local uid = unique_id("");
	tmp_notice_storage[uid] = n;

	local output = "";
	if ( n?$src )
		{
		add n$email_delay_tokens["hostnames-src"];
		when [n, uid, output] ( local src_name = lookup_addr(n$src) )
			{
			output = string_cat("orig/src hostname: ", src_name, "\n");
			tmp_notice_storage[uid]$email_body_sections += output;
			delete tmp_notice_storage[uid]$email_delay_tokens["hostnames-src"];
			}
		}
	if ( n?$dst )
		{
		add n$email_delay_tokens["hostnames-dst"];
		when [n, uid, output] ( local dst_name = lookup_addr(n$dst) )
			{
			output = string_cat("resp/dst hostname: ", dst_name, "\n");
			tmp_notice_storage[uid]$email_body_sections += output;
			delete tmp_notice_storage[uid]$email_delay_tokens["hostnames-dst"];
			}
		}
	}
