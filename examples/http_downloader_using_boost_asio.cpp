/* based on http://www.boost.org/doc/libs/1_61_0/doc/html/boost_asio/example/cpp03/echo/blocking_tcp_echo_client.cpp */

#include <iostream>
#include <fstream>
#include <memory>
#include <libgen.h> /* for basename */
#include <cstring>
#include <boost/asio.hpp>
#include "../http_parser.hpp"

using boost::asio::ip::tcp;
using namespace http;

std::string determine_file_name(const std::string& url_path,
        const http::response_head& rh)
{
    (void) rh;
    // It would make sense to get file name from Content-Disposition header.
    // The solution here is much simpler so that the example can be short.
    std::unique_ptr<char, decltype(&std::free)>  url_path_copy
    		{ strdup(url_path.c_str()), std::free };
    if (!url_path_copy) {
    	throw std::bad_alloc();
    }
    return basename(url_path_copy.get());
}

int main(int argc, char* argv[])
{
    try {
        if (argc != 2) {
            std::cerr << "Usage: " << argv[0] << " <URL>" << std::endl;
            return 1;
        }

        url_t url;
        bool url_parsed_ok = false;
        try {
            url = parse_url(argv[1]);
            url_parsed_ok = true;
        } catch (const url_parse_error&) {
        }
        if (!url_parsed_ok || url.host.empty()) {
            std::cerr << "This does not appear to be a valid URL of a HTTP resource: "
            << argv[1] << std::endl;
            return 1;
        }
        if (url.schema != "http") {
            std::cerr << "This program only supports plain HTTP." << std::endl;
            return 1;
        }
        if (0 == url.port) { // no port specified explicitly in the URL
            url.port = 80; // good as long as we only support http://
        }

        std::ostringstream ss;
        ss << "GET " << url.path;
        if (!url.query.empty()) {
            ss << '?' << url.query;
        }
        ss << " HTTP/1.1\r\n"
                << "Host: " << url.host << "\r\n"
                << "Connection: close\r\n"
                << "\r\n";
        const std::string request = ss.str();
        std::cout << request << std::endl;

        boost::asio::io_service io_service;

        tcp::resolver resolver(io_service);
        tcp::resolver::query query(tcp::v4(), url.host, std::to_string(url.port));
        tcp::resolver::iterator it = resolver.resolve(query);

        tcp::socket socket(io_service);
        std::cout << "Connecting to " << url.host << ':' << url.port << "... "
                << std::flush;
        boost::asio::connect(socket, it);
        std::cout << "done\nSending request." << std::endl;
        boost::asio::write(socket, boost::asio::buffer(request));

        std::cout << "Reading response." << std::endl;
        std::string file_name;
        std::ofstream output_file;
        output_file.exceptions(std::ofstream::failbit | std::ofstream::badbit);
        bool completed = false;
        auto my_callback = [&] (const http::response_head& response,
                const char *body_part, std::size_t body_part_length, bool finished) {
            if (!output_file.is_open()) {
                file_name = determine_file_name(url.path, response);
                std::cout << "Saving to " << file_name << std::endl;
                output_file.open(file_name,
                        std::ios::out | std::ios::trunc | std::ios::binary);
            }
            output_file.write(body_part, body_part_length);
            completed = finished;
            if (completed) {
                std::cout << "Done." << std::endl;
            }
        };
        http::big_response_parser parser(my_callback);
        parser.set_max_headers_length(1024 * 1024);
        while (!completed) {
            boost::system::error_code ec;
            char reply[2048];
            size_t reply_length = boost::asio::read(socket,
                    boost::asio::buffer(reply, sizeof(reply)), ec);
            if (reply_length > 0U) {
                parser.feed(reply, reply_length);
            }
            if (boost::asio::error::eof == ec) {
                parser.feed_eof();
            } else if (ec) {
                throw boost::system::system_error(ec);
            }
        }
    } catch (const std::runtime_error& e) {
        std::cerr << "Interrupted by exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
