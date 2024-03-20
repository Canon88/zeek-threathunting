event new_connection(c: connection)
{
    Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
    Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
}