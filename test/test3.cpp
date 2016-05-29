#undef NDEBUG
#include <cassert>
#include <iostream>
#include "../HttpParser.hpp"

int main()
{
	using namespace std;
	using namespace http;

	RequestParser parser;

	const std::string input = "definitely not a valid HTTP request";

	bool parseErrorOccurred = false;
	try {
		parser.feed(input.cbegin(), input.cend());
		parser.feedEof();
	} catch (const RequestParseError& e) {
		//cerr << e.what() << endl;
		parseErrorOccurred = true;
	}
	assert(parseErrorOccurred);

	cout << "If you can see this message, the test passed OK" << endl;
	return 0;
}
