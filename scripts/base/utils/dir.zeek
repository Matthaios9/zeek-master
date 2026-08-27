@load base/utils/exec
@load base/frameworks/reporter
@load base/utils/paths

module Dir;

export {


	option polling_interval = 30sec;












	global monitor: function(dir: string, callback: function(fname: string),
	                         poll_interval: interval &default=polling_interval);
}

event Dir::monitor_ev(dir: string, last_files: set[string],
                      callback: function(fname: string),
                      poll_interval: interval)
	{
	when [dir, last_files, callback, poll_interval] ( local result = Exec::run(Exec::Command($cmd=fmt("ls -1 %s/", safe_shell_quote(dir)))) )
		{
		if ( result$exit_code != 0 )
			{
			Reporter::warning(fmt("Requested monitoring of nonexistent directory (%s).", dir));
			return;
			}

		local current_files: set[string] = set();
		local files: vector of string = vector();

		if ( result?$stdout )
			files = result$stdout;

		for ( i in files )
			{
			if ( files[i] !in last_files )
				callback(build_path_compressed(dir, files[i]));
			add current_files[files[i]];
			}

		schedule poll_interval
			{
			Dir::monitor_ev(dir, current_files, callback, poll_interval)
			};
		}
	}

function monitor(dir: string, callback: function(fname: string),
                 poll_interval: interval &default=polling_interval)
	{
	event Dir::monitor_ev(dir, set(), callback, poll_interval);
	}
