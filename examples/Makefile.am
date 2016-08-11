if CAN_BUILD_EXAMPLES
noinst_PROGRAMS = http_server_using_boost_asio http_downloader_using_boost_asio

http_server_using_boost_asio_SOURCES = http_server_using_boost_asio.cpp
http_server_using_boost_asio_LDADD = -lboost_system

http_downloader_using_boost_asio_SOURCES = http_downloader_using_boost_asio.cpp
http_downloader_using_boost_asio_LDADD = -lboost_system
http_downloader_using_boost_asio_LDFLAGS = -pthread
# Apparently boost::asio::ip::tcp::resolver needs -pthread
endif
