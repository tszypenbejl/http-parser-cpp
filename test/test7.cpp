#undef NDEBUG
#include <cassert>
#include <iostream>
#include <vector>
#include <list>
#include "../HttpParser.hpp"

int main()
{
	using namespace std;
	using namespace http;

	char input1[] =
			"HTTP/1.1 200 OK\r\n"
			"Date: Tue, 07 Jun 2016 05:16:11 -0500\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: 15\r\n"
			"\r\n"
			"Hello, World!\r\n";

	char input2[] =
			"HTTP/1.1 200 OK\r\n"
			"Date: Tue, 07 Jun 2016 05:16:11 -0500\r\n"
			"Content-Type: text/plain\r\n"
			"Content-Length: 60\r\n"
			"\r\n"
			"Hello, World!\r\n"
			"Hello, World!\r\n"
			"Hello, World!\r\n"
			"Hello, World!\r\n";

	std::string sinput;
	sinput.append(input1);
	sinput.append(input2);
	std::list<char> linput(sinput.begin(), sinput.end());

	unsigned responsesParsed = 0;
	bool exceptionThrown = false;

	auto responseConsumer = [&responsesParsed] (Response&&) -> void { ++responsesParsed; };

	ResponseParser sparser(responseConsumer);
	ResponseParser lparser(responseConsumer);

	sparser.setMaxResponseLength(sizeof(input1) - 1);
	lparser.setMaxResponseLength(sizeof(input1) - 1);

	try {
		sparser.feed(sinput.cbegin(), sinput.cend());
	} catch (const ResponseTooBig&) {
		exceptionThrown = true;
	}

	assert(1 == responsesParsed);
	assert(exceptionThrown);

	responsesParsed = 0;
	exceptionThrown = false;

	try {
		lparser.feed(linput.cbegin(), linput.cend());
	} catch (const ResponseTooBig&) {
		exceptionThrown = true;
	}
	
	assert(1 == responsesParsed);
	assert(exceptionThrown);

	cout << "If you can see this message, the test passed OK" << endl;
	return 0;
}
