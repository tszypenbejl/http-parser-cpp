#undef NDEBUG
#include <cassert>
#include <iostream>
#include <vector>
#include <list>
#include "testhelpers.hpp"
#include "../HttpParser.hpp"

int main()
{
	using namespace std;
	using namespace http;

	ResponseParser parser;

	char input[] =
			"HTTP/1.1 200 OK\r\n"
			"Date: Tue, 07 Jun 2016 05:16:11 -0500\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: 15\r\n"
			"\r\n"
			"Hello, World!\r\n";
	std::string sinput(input);
	std::vector<char> vinput(sinput.begin(), sinput.end());
	std::list<char> linput(vinput.begin(), vinput.end());

	parser.feed(input, sizeof(input) - 1);
	parser.feed(input, input + sizeof(input) - 1);
	parser.feed(sinput.cbegin(), sinput.cend());
	parser.feed(vinput.cbegin(), vinput.cend());
	parser.feed(linput.cbegin(), linput.cend());
	parser.feed_eof();

	assert(parser.parsedResponses.size() == 5);
	assert(parser.parsedResponses.at(0) == parser.parsedResponses.at(1));
	assert(parser.parsedResponses.at(0) == parser.parsedResponses.at(2));
	assert(parser.parsedResponses.at(0) == parser.parsedResponses.at(3));
	assert(parser.parsedResponses.at(0) == parser.parsedResponses.at(4));

	const response& r = parser.parsedResponses.front();
	assert(200U == r.status_code());
	assert("OK" == r.status_text());
	assert(1 == r.http_version().major() && 1 == r.http_version().minor());
	assert(3 == r.header_count());
	assert("Tue, 07 Jun 2016 05:16:11 -0500" == r.get_header("date"));
	assert("text/plain" == r.get_header("content-type"));
	assert("15" == r.get_header("content-length"));
	assert("Hello, World!\r\n" == r.body());
	//std::cout << r << std::endl;

	parser.parsedResponses.clear();

	cout << "If you can see this message, the test passed OK" << endl;
	return 0;
}
