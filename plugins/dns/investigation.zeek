redef record DNS::Info += {
    threathunting: bool &log &optional;
};

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if (c?$threathunting)
        c$dns$threathunting = T;
}

hook DNS::log_policy(rec: DNS::Info, id: Log::ID, filter: Log::Filter)
{
    if ( filter$name == "dns_investigation" ) {
        if (! rec?$threathunting) {
            break;
        }
    }
}

event zeek_init()
{
    ## Define a new log filter tailored for DNS investigations.
    local filter: Log::Filter = [
        $name="dns_investigation",
        $path="dns-investigation"
    ];

    ## Incorporate the defined filter into the standard DNS log stream.
    Log::add_filter(DNS::LOG, filter);
}
