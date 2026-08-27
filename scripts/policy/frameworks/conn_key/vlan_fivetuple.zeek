




redef record conn_id_ctx += {

	vlan: int &log &optional;

	inner_vlan: int &log &optional;
};

redef ConnKey::factory = ConnKey::CONNKEY_VLAN_FIVETUPLE;
