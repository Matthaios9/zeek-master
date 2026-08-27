module NTP;

export {


	const modes: table[count] of string = {
		[1] = "symmetric active",
		[2] = "symmetric passive",
		[3] = "client",
		[4] = "server",
		[5] = "broadcast server",
		[6] = "broadcast client",
		[7] = "reserved",
	} &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;
}
