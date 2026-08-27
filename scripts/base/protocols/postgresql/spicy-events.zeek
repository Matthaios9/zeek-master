




global PostgreSQL::ssl_request: event(c: connection);






global PostgreSQL::ssl_reply: event(c: connection, data: string);











global PostgreSQL::authentication_request: event(c: connection, identifier: count, data: string);








global PostgreSQL::authentication_ok: event(c: connection);









global PostgreSQL::authentication_response: event(c: connection, data: string);









global PostgreSQL::startup_parameter: event(c: connection, name: string, value: string);








global PostgreSQL::startup_message: event(c: connection, major: count, minor: count);






global PostgreSQL::ready_for_query: event(c: connection, transaction_status: string);






global PostgreSQL::simple_query: event(c: connection, query: string);










global PostgreSQL::error_response_identified_field: event(c: connection, code: string, value: string);






global PostgreSQL::error_response: event(c: connection);










global PostgreSQL::notice_response_identified_field: event(c: connection, code: string, value: string);






global PostgreSQL::notice_response: event(c: connection);






global PostgreSQL::data_row: event(c: connection, column_values: count);









global PostgreSQL::parameter_status: event(c: connection, name: string, value: string);








global PostgreSQL::backend_key_data: event(c: connection, process_id: count, secret_key: count);




global PostgreSQL::terminate: event(c: connection);


global PostgreSQL::not_implemented: event(c: connection, is_orig: bool, typ: string, chunk: string);
