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

	RequestParser parser;

	char input[] = "GET /formhandler?par1=koko+jumbo&par2=kinematograf HTTP/1.1\r\nHost: example.com\r\n\r\n";
	std::string sinput(input);
	std::vector<char> vinput(sinput.begin(), sinput.end());
	std::list<char> linput(vinput.begin(), vinput.end());

	parser.feed(input, sizeof(input) - 1);
	parser.feed(input, input + sizeof(input) - 1);
	parser.feed(sinput.cbegin(), sinput.cend());
	parser.feed(vinput.cbegin(), vinput.cend());
	parser.feed(linput.cbegin(), linput.cend());
	parser.feed_eof();

	assert(parser.parsedRequests.size() == 5);
	assert(parser.parsedRequests.at(0) == parser.parsedRequests.at(1));
	assert(parser.parsedRequests.at(0) == parser.parsedRequests.at(2));
	assert(parser.parsedRequests.at(0) == parser.parsedRequests.at(3));
	assert(parser.parsedRequests.at(0) == parser.parsedRequests.at(4));

	const Request& r = parser.parsedRequests.front();
	assert(HTTP_GET == r.type);
	assert(1 == r.http_version_.major() && 1 == r.http_version_.minor());
	assert("/formhandler?par1=koko+jumbo&par2=kinematograf" == r.url);
	assert(1 == r.header_count());

	assert(r.has_header("Host"));
	assert(r.has_header("HOST"));
	assert(r.has_header("host"));
	assert(r.has_header("hOsT"));
	assert("example.com" == r.get_header("host"));
	assert("example.com" == r.get_header("host", "value-if-not-found"));
	assert(!r.has_header("Content-Type"));
	assert("text/plain" == r.get_header("Content-Type", "text/plain"));
	bool headerNotFoundErrorOccurred = false;
	try {
		(void) r.get_header("Content-Type");
	} catch (const header_not_found_error&) {
		//cerr << e.what() << endl;
		headerNotFoundErrorOccurred = true;
	}
	assert(headerNotFoundErrorOccurred);

	parser.parsedRequests.clear();

	cout << "If you can see this message, the test passed OK" << endl;
	return 0;
}
