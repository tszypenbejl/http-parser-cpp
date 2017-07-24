#undef NDEBUG
#include <cassert>
#include <iostream>
#include "../http_parser.hpp"

int main()
{
	using namespace std;
	using namespace http;

	request_parser parser;

	const std::string input = "definitely not a valid HTTP request";

	bool parseErrorOccurred = false;
	try {
		parser.feed(input.cbegin(), input.cend());
		parser.feed_eof();
	} catch (const request_parse_error& e) {
		parseErrorOccurred = true;
	}
	assert(parseErrorOccurred);

	cout << "If you can see this message, the test passed OK" << endl;
	return 0;
}
