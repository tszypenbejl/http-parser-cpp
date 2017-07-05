#pragma once
#include "../HttpParser.hpp"

bool operator==(const http::HttpVersion& lhs, const http::HttpVersion& rhs)
{
	return lhs.major == rhs.major && lhs.minor == rhs.minor;
}

bool operator==(const http::Request& lhs, const http::Request& rhs)
{
	return lhs.type == rhs.type && lhs.httpVersion == rhs.httpVersion
			&& lhs.url == rhs.url && lhs.all_headers() == rhs.all_headers()
			&& lhs.body == rhs.body;
}

bool operator==(const http::Response& lhs, const http::Response& rhs)
{
	return lhs.statusCode == rhs.statusCode && lhs.statusText == rhs.statusText
			&& lhs.httpVersion == rhs.httpVersion && lhs.all_headers() == rhs.all_headers()
			&& lhs.body == rhs.body;
}
