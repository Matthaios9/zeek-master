

@if ( have_spicy_analyzers() )















global syslog_message: event(c: connection, facility: count, severity: count, msg: string);

@endif
