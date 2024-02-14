redef record Conn::Info += {
    threathunting: bool &log &optional;
};

event connection_state_remove(c: connection) &priority=5
{
	if (c?$threathunting)
		c$conn$threathunting = T;
}

hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
{
    if ( filter$name == "conn_investigation" ) {
        if (! rec?$threathunting) {
            break;
        }
    }
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
