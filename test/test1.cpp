#undef NDEBUG
#include <cassert>
#include <iostream>
#include <vector>
#include <list>
#include "../HttpParser.hpp"

bool operator==(const http::Request& lhs, const http::Request& rhs)
{
	return lhs.type == rhs.type && lhs.url == rhs.url && lhs.headers == rhs.headers && lhs.body == rhs.body;
}

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
	parser.feedEof();

	assert(parser.parsedRequests.size() == 5);
	assert(parser.parsedRequests.at(0) == parser.parsedRequests.at(1));
	assert(parser.parsedRequests.at(0) == parser.parsedRequests.at(2));
	assert(parser.parsedRequests.at(0) == parser.parsedRequests.at(3));
	assert(parser.parsedRequests.at(0) == parser.parsedRequests.at(4));
	//std::cout << parser.parsedRequests.front() << std::endl;

	parser.parsedRequests.clear();

	cout << "If you can see this message, the test passed OK" << endl;
	return 0;
}
