#undef NDEBUG
#include <cassert>
#include <iostream>
#include "../HttpParser.hpp"

int main()
{
	using namespace std;
	using namespace http;

	url_t url;

	url = parse_url("http://hostname/");
	assert("http" == url.schema);
	assert("hostname" == url.host);
	assert("/" == url.path);
	//cout << url << endl;

	url = parse_url("hostname:8080", true);
	assert("hostname" == url.host);
	assert(8080U == url.port);
	//cout << url << endl;

	url = parse_url("/test");
	assert("/test" == url.path);
	//cout << url << endl;

	url = parse_url("/test?par1=koko+jumbo&par2=kinematograf");
	assert("/test" == url.path);
	assert("par1=koko+jumbo&par2=kinematograf" == url.query);
	//cout << url << endl;

	cout << "If you can see this message, the test passed OK" << endl;
	return 0;
}
