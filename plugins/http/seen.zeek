@load base/utils/addrs

export {
	redef enum Intel::Where += {
		HTTP::IN_TRUE_CLIENT_IP_HEADER,
	};
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( is_orig )
    {
    switch ( name )
        {
        case "TRUE-CLIENT-IP":
        if ( is_valid_ip(value) )
            {
            local addrs = extract_ip_addresses(value);
            for ( i in addrs )
                {
                Intel::seen([$host=to_addr(addrs[i]),
                                $indicator_type=Intel::ADDR,
                                $conn=c,
                                $where=HTTP::IN_TRUE_CLIENT_IP_HEADER]);
                }
            }
        break;
        }
    }
}