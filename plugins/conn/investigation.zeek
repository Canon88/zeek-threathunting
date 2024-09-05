@load ../__load__
@load ./seen

# Loading necessary scripts for intelligence framework and expiration handling.
module ThreatHunting;

redef record connection += {
    threathunting: bool &log &optional;
};

# Hook for filtering Intel log entries based on predefined criteria.
hook Intel::seen_policy(s: Intel::Seen, found: bool)
{
    # Default, the ThreatHunting field is added to the connection.
    if ( (found) && ("CONN" in enable_module) )
        s$conn$threathunting = T;
}

redef record Conn::Info += {
    threathunting: bool &log &optional;
};

hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
{
    if ( filter$name == "conn_investigation" ) {
        if (! rec?$threathunting) {
            return;
        }
    }
}

event connection_state_remove(c: connection)
{
	if (c?$threathunting)
		c$conn$threathunting = T;
}

event zeek_init()
{
    ## Define a new log filter tailored for Conn investigations.
    local filter: Log::Filter = [
        $name="conn_investigation", 
        $path="conn-investigation"
    ];

    ## Incorporate the defined filter into the standard Conn log stream.
    Log::add_filter(Conn::LOG, filter);
}
