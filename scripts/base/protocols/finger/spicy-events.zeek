

@if ( have_spicy_analyzers() )















global finger_request: event(c: connection, full: bool, username: string, hostname: string);











global finger_reply: event(c: connection, reply_line: string);

@endif
