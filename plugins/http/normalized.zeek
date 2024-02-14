event zeek_init()
{
    # handles HTTP
    local http_f = Log::get_filter(HTTP::LOG, "http_investigation");
    http_f$field_name_map = table(
        ["event_type"] = "event.kind",
        ["id.orig_h"] = "source.ip",
        ["id.orig_p"] = "source.port",
        ["id.resp_h"] = "destination.ip",
        ["id.resp_p"] = "destination.port",

        ["status_msg"] = "status",
        ["host"] = "url.domain",
        ["uri"] = "url.original",
        ["url_path"] = "url.path",
        ["method"] = "http.request.method",
        ["referrer"] = "http.request.referrer",
        ["user_agent"] = "http.request.user-agent",
        ["cookie"] = "http.request.cookie",
        ["status_code"] = "http.response.status_code",

        ["request_headers"] = "http.request.headers",
        ["request_body"] = "http.request.body.content",
        ["request_body_len"] = "http.request.body.bytes",

        ["response_headers"] = "http.response.headers",
        ["response_body"] = "http.response.body.content",
        ["response_body_len"] = "http.response.body.bytes",
    );
    Log::add_filter(HTTP::LOG, http_f);
}