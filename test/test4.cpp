#undef NDEBUG
#include <cassert>
#include <iostream>
#include "../HttpParser.hpp"

int main()
{
	using namespace std;
	using namespace http;

	const std::string input =
			"POST /handleform HTTP/1.1\r\n"
			"Host: example.com\r\n"
			"Content-Type: application/x-www-form-urlencoded\r\n"
			"Transfer-Encoding: chunked\r\n"
			"\r\n"
			"11; length is given in hex and this text should be ignored\r\n"
			"par1=koko+jumbo&p\r\n"
			"10\r\n"
			"ar2=kinematograf\r\n"
			"0\r\n"
			"LateHeader1: this example\r\n"
			"LateHeader2: consists of just two chunks\r\n"
			"\r\n";

	RequestParser parser;
	parser.feed(input.cbegin(), input.cend());
	parser.feedEof();
	assert(1 == parser.parsedRequests.size());
	//cout << parser.parsedRequests.front() << endl;
	//cout << parser.parsedRequests.front().body << endl;

	const Request r = std::move(parser.parsedRequests.front());
	parser.parsedRequests.pop_front();

	assert(HTTP_POST == r.type);
	assert(1 == r.httpVersion.major && 1 == r.httpVersion.minor);
	assert("/handleform" == r.url);
	assert(5 == r.headers.size());
	assert(1 == r.headers.count("Host"));
	assert(1 == r.headers.count("Content-Type"));
	assert(1 == r.headers.count("Transfer-Encoding"));
	assert(1 == r.headers.count("LateHeader1"));
	assert(1 == r.headers.count("LateHeader2"));
	assert("example.com" == r.headers.find("Host")->second);
	assert("application/x-www-form-urlencoded" ==
			r.headers.find("Content-Type")->second);
	assert("chunked" == r.headers.find("Transfer-Encoding")->second);
	assert("this example" == r.headers.find("LateHeader1")->second);
	assert("consists of just two chunks" == r.headers.find("LateHeader2")->second);
	assert("par1=koko+jumbo&par2=kinematograf" == r.body);

	cout << "If you can see this message, the test passed OK" << endl;
	return 0;
}
