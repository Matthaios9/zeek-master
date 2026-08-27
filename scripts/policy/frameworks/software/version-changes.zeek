



@load base/frameworks/notice
@load base/frameworks/software

module Software;

export {
	redef enum Notice::Type += {




		Software_Version_Change,
	};




	option interesting_version_changes: set[string] = {};
}

event Software::version_change(old: Software::Info, new: Software::Info)
	{
	if ( old$name !in interesting_version_changes )
		return;

	local msg = fmt("%.6f %s '%s' version changed from %s to %s",
	                network_time(), old$software_type, old$name,
	                software_fmt_version(old$version),
	                software_fmt_version(new$version));

	NOTICE(Notice::Info($note=Software_Version_Change, $src=new$host,
	                    $msg=msg, $sub=software_fmt(new)));
	}
