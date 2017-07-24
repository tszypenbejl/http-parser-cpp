#pragma once
#include "../http_parser.hpp"

bool operator==(const http::request& lhs, const http::request& rhs)
{
    return lhs.method() == rhs.method() && lhs.http_version() == rhs.http_version()
            && lhs.url() == rhs.url() && lhs.all_headers() == rhs.all_headers()
            && lhs.body() == rhs.body();
}

bool operator==(const http::response& lhs, const http::response& rhs)
{
    return lhs.status_code() == rhs.status_code() && lhs.status_text() == rhs.status_text()
            && lhs.http_version() == rhs.http_version() && lhs.all_headers() == rhs.all_headers()
            && lhs.body() == rhs.body();
}
