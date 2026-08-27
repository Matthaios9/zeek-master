


module Finger;

export {

	const ports = { 79/tcp } &redef;
}

event zeek_init() &priority=5
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_FINGER, ports);
	}
