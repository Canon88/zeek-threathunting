# add the Intel::Seen record to the ThreatHunting module
redef record Intel::MetaData += {
    level: string &optional;
};

redef record Intel::Info += {
    level: string &log &optional;
};

hook Intel::extend_match(info: Intel::Info, s: Intel::Seen, items: set[Intel::Item])
    {
    for ( item in items )
        {
        if ( item$meta?$level )
            {
            local level = item$meta$level;
            info$level = level;
            }
        else
            info$level = "low";
        }
    }