#include <iostream>
#include <cassert>
#include <vector>

#define HTTP_PARSER_CPP_IS_CONTIGUOUS_MEMORY_FORWARD_ITERATOR_EXTRA_SPECIALIZATIONS \
	template<> \
	struct IsContiguousMemoryForwardIterator \
			<typename std::string::iterator>: std::true_type {}; \
	template<> \
	struct IsContiguousMemoryForwardIterator \
			<typename std::string::const_iterator>: std::true_type {};

#include "HttpParser.hpp"


bool operator==(const http::HttpRequest& lhs, const http::HttpRequest& rhs)
{
	return lhs.type == rhs.type && lhs.url == rhs.url && lhs.headers == rhs.headers && lhs.body == rhs.body;
}

int main()
{
	using namespace http;
	HttpRequestParser myParser;

	char input[] = "GET /formhandler?par1=koko+jumbo&par2=kinematograf HTTP/1.1\r\nHost: example.com\r\n\r\n";
	myParser.feed(input, sizeof(input) - 1);
	//myParser.feedEof();

	myParser.feed(input, input + sizeof(input) - 1);
	myParser.feedEof();

	assert(myParser.parsedRequests.size() == 2);
	assert(myParser.parsedRequests.at(0) == myParser.parsedRequests.at(1));

	std::vector<char> vinput(input, input + sizeof(input) - 1);
	myParser.feed(vinput.cbegin(), vinput.cend());

	std::string sinput(input);
	myParser.feed(sinput.cbegin(), sinput.cend());

	while (!myParser.parsedRequests.empty()) {
		std::cout << myParser.parsedRequests.front() << std::endl;
		myParser.parsedRequests.pop_front();
	}
	return 0;
}
