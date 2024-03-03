export {
	redef enum Intel::Where += {
		SSH::AUTH_FAILED,
        SSH::AUTH_SUCCESSFUL,
	};
}

event ssh_auth_attempted(c: connection, authenticated: bool)
{
    local id = c$id;
    if (authenticated)
        {
        Intel::seen([$host=id$orig_h,
                        $conn=c,
                        $where=SSH::AUTH_SUCCESSFUL]);
        }
    else 
        {
        Intel::seen([$host=id$orig_h,
                        $conn=c,
                        $where=SSH::AUTH_FAILED]);
        }
}