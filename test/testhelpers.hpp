#pragma once
#include "../HttpParser.hpp"

bool operator==(const http::request& lhs, const http::request& rhs)
{
	return lhs.method() == rhs.method() && lhs.http_version() == rhs.http_version()
			&& lhs.url() == rhs.url() && lhs.all_headers() == rhs.all_headers()
			&& lhs.body() == rhs.body();
}

bool operator==(const http::Response& lhs, const http::Response& rhs)
{
	return lhs.statusCode == rhs.statusCode && lhs.statusText == rhs.statusText
			&& lhs.http_version_ == rhs.http_version_ && lhs.all_headers() == rhs.all_headers()
			&& lhs.body == rhs.body;
}
