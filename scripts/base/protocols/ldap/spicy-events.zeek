




















global LDAP::message: event(
  c: connection,
  message_id: int,
  opcode: LDAP::ProtocolOpcode,
  result: LDAP::ResultCode,
  matched_dn: string,
  diagnostic_message: string,
  object: string,
  argument: string
);














global LDAP::bind_request: event(
  c: connection,
  message_id: int,
  version: int,
  name: string,
  auth_type: LDAP::BindAuthType,
  auth_info: string
);






















global LDAP::search_request: event (
  c: connection,
  message_id: int,
  base_object: string,
  scope: LDAP::SearchScope,
  deref: LDAP::SearchDerefAlias,
  size_limit: int,
  time_limit: int,
  types_only: bool,
  filter: string,
  attributes: vector of string
);








global LDAP::search_result_entry: event (
  c: connection,
  message_id: int,
  object_name: string
);










global LDAP::extended_request: event (
  c: connection,
  message_id: int,
  request_name: string,
  request_value: string
);












global LDAP::extended_response: event (
  c: connection,
  message_id: int,
  result: LDAP::ResultCode,
  response_name: string,
  response_value: string
);





global LDAP::starttls: event(c: connection);
