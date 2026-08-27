

module IGMP;

export {


	type MessageType: enum {
		MEMBERSHIP_QUERY     = 0x11,
		MEMBERSHIP_REPORT_V1 = 0x12,
		MEMBERSHIP_REPORT_V2 = 0x16,
		LEAVE_GROUP          = 0x17,
		MEMBERSHIP_REPORT_V3 = 0x22,
		BAD_CHECKSUM         = 0x00
	};



	type GroupType: enum {
		MODE_IS_INCLUDE        = 1,
		MODE_IS_EXCLUDE        = 2,
		CHANGE_TO_INCLUDE_MODE = 3,
		CHANGE_TO_EXCLUDE_MODE = 4,
		ALLOW_NEW_SOURCES      = 5,
		BLOCK_OLD_SOURCES      = 6
	};



	type Group: record {

		group_type:     GroupType;

		aux_data_len:   count;

		num_sources:    count;

		multicast_addr: addr;

		sources:        vector of addr;

		aux_data:       string;
	};

}
