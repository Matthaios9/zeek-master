

@load base/protocols/dns

redef record DNS::Info$opcode -= { &log };
redef record DNS::Info$opcode_name -= { &log };
