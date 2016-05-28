/* Based on http://www.boost.org/doc/libs/1_61_0/doc/html/boost_asio/example/cpp11/echo/async_tcp_echo_server.cpp */

#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include "../HttpParser.hpp"

using boost::asio::ip::tcp;
using http::RequestParser;
using http::Request;
using http::ParseError;

class Session: public std::enable_shared_from_this<Session>
{
	static const size_t inputBufLen = 512;

private:
	tcp::socket socket;
	char inputBuf[inputBufLen];
	RequestParser reqParser;

public:
	Session(tcp::socket socket)
		: socket(std::move(socket)),
			reqParser([this](Request&& r) { onRequestReceived(r); }) {}

	void start() { doRead(); }

private:
	void doRead()
	{
		auto self(shared_from_this());
		socket.async_read_some(boost::asio::buffer(inputBuf, inputBufLen),
				[this, self](boost::system::error_code ec, std::size_t length)
				{
					if (ec) {
						return;
					}
					try {
						reqParser.feed(inputBuf, length);
						doRead();
					} catch (const ParseError&) {
						static const std::string response =
								"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n"
								"Content-Length: 17\r\n\r\n400 Bad Request\r\n";
						doWrite(response);
					}
				});
	}

	void doWrite(const std::string& response)
	{
		// FIXME: response param reference must remain valid indefinitely,
		//        perhaps writeCallback could be forced to store a copy of it.
		auto self(shared_from_this());
		auto writeCallback = [self](boost::system::error_code, std::size_t) {};
		boost::asio::async_write(socket, boost::asio::buffer(response), writeCallback);
	}

	void onRequestReceived(Request& req)
	{
		static const std::string responseOk =
				"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
				"Content-Length: 15\r\n\r\nHello, World!\r\n";
		static const std::string response404 =
				"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n"
				"Content-Length: 15\r\n\r\n404 Not Found\r\n";

		const std::string& response =
				"/" == req.url ? responseOk : response404;

		// TODO: must check if request method is GET

		doWrite(response);
	}
};

class Server
{
	tcp::acceptor acceptor;
	tcp::socket socket;

public:
	Server(boost::asio::io_service& io_service, short port)
		: acceptor(io_service, tcp::endpoint(tcp::v4(), port)),
			socket(io_service) { doAccept(); }

private:
	void doAccept()
	{
		acceptor.async_accept(socket, [this](boost::system::error_code ec)
				{
					if (!ec) {
						std::make_shared<Session>(std::move(socket))->start();
					}
					doAccept();
				});
	}
};

int main(int argc, char* argv[])
{
	if (argc != 2) {
		std::cerr << "Usage: http_server_using_boost_asio <port>\n";
		return 1;
	}
	const int portNum = std::atoi(argv[1]);

	try	{
		boost::asio::io_service ioService;
		Server server(ioService, portNum);
		ioService.run();
	} catch (const std::exception& e) {
		std::cerr << "Interrupted by exception: " << e.what() << "\n";
	}
	return 0;
}
