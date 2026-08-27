








global IGMP::message: event(packet: raw_pkt_hdr, msg_type: IGMP::MessageType);






global IGMP::membership_query: event(source: addr, group_addr: addr);






global IGMP::membership_report_v1: event(source: addr, group_addr: addr);






global IGMP::membership_report_v2: event(source: addr, group_addr: addr);






global IGMP::leave_group: event(source: addr, group_addr: addr);






global IGMP::membership_report_v3: event(source: addr, groups: vector of IGMP::Group);
