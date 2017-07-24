#undef NDEBUG
#include <cassert>
#include <iostream>
#include "../http_parser.hpp"

int main()
{
	using namespace std;
	using namespace http;

	request_parser parser;

	const std::string input =
			"GET /demo HTTP/1.1\r\n"
			"Upgrade: WebSocket\r\n"
			"Connection: Upgrade\r\n"
			"Host: example.com\r\n"
			"Origin: http://example.com\r\n"
			"WebSocket-Protocol: sample\r\n"
			"\r\n"
			"some non-http data apparently sent with the assumption that\n"
			"the server supports http upgrades and will complete the upgrade\n"
			"handshake by responding with appropriate headers.";

	parser.feed(input.cbegin(), input.cend());

	assert(1 == parser.get_request_count());
	const request r = parser.pop_request();
	assert("/demo" == r.url());
	assert("WebSocket" == r.get_header("Upgrade"));

	assert(
			"some non-http data apparently sent with the assumption that\n"
			"the server supports http upgrades and will complete the upgrade\n"
			"handshake by responding with appropriate headers."
					== parser.protocol_upgrade_data());

	cout << "If you can see this message, the test passed OK" << endl;
	return 0;
}
