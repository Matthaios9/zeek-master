





@load base/frameworks/notice

module Conn;

export {
	redef enum Notice::Type += {

		Retransmission_Inconsistency,

		Content_Gap,
	};
}

event rexmit_inconsistency(c: connection, t1: string, t2: string, tcp_flags: string)
	{
	NOTICE(Notice::Info($note=Retransmission_Inconsistency,
	                    $conn=c,
	                    $msg=fmt("%s rexmit inconsistency (%s) (%s) [%s]",
	                             id_string(c$id), t1, t2, tcp_flags),
	                    $identifier=fmt("%s", c$id)));
	}

event content_gap(c: connection, is_orig: bool, seq: count, length: count)
	{
	NOTICE(Notice::Info($note=Content_Gap, $conn=c,
	                    $msg=fmt("%s content gap (%s %d/%d)",
	                             id_string(c$id), is_orig ? ">" : "<", seq, length)));
	}
