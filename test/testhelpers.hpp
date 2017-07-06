#pragma once
#include "../HttpParser.hpp"

bool operator==(const http::Request& lhs, const http::Request& rhs)
{
	return lhs.type == rhs.type && lhs.http_version_ == rhs.http_version_
			&& lhs.url == rhs.url && lhs.all_headers() == rhs.all_headers()
			&& lhs.body == rhs.body;
}

bool operator==(const http::Response& lhs, const http::Response& rhs)
{
	return lhs.statusCode == rhs.statusCode && lhs.statusText == rhs.statusText
			&& lhs.http_version_ == rhs.http_version_ && lhs.all_headers() == rhs.all_headers()
			&& lhs.body == rhs.body;
}
