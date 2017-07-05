#pragma once

#include <http_parser.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <deque>
#include <type_traits>
#include <functional>
#include <iterator>
#include <cstdio> /* for snprintf */
#include <cassert>
#if defined(WIN32) || defined(WIN64) /* TODO: check if that actually helps*/
#include <cstring>
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif

namespace http {

using protocol_upgrade_handler =
		std::function<void(const char* begin, const char* end)>;

class parse_error : public std::runtime_error
{
public:
	using runtime_error::runtime_error;
};

class too_big_error : public std::runtime_error
{
public:
	using runtime_error::runtime_error;
};

class request_parse_error : public parse_error
{
public:
	using parse_error::parse_error;
};

class response_parse_error : public parse_error
{
public:
	using parse_error::parse_error;
};

class request_too_big : public too_big_error
{
public:
	using too_big_error::too_big_error;
};

class request_headers_too_big : public too_big_error
{
public:
	using too_big_error::too_big_error;
};

class response_too_big : public too_big_error
{
public:
	using too_big_error::too_big_error;
};

class response_headers_too_big : public too_big_error
{
public:
	using too_big_error::too_big_error;
};

class url_parse_error : public parse_error
{
public:
	using parse_error::parse_error;
};

class header_not_found_error : public std::runtime_error
{
public:
	using runtime_error::runtime_error;
};

namespace detail {

template<typename Parser>
class callbacks
{
	template<typename MethodT, typename... ArgsT>
	inline static int call(http_parser* p, MethodT method, ArgsT... args)
	{
		Parser& parser = *((Parser*) p->data);
		try {
			return (parser.*method)(args...);
		} catch (...) {
			parser.callbackException = std::current_exception();
		}
		return -1;
		
	}

public:
	static int on_message_begin(http_parser* p) noexcept
			{ return call(p, &Parser::on_message_begin); }

	static int on_url(http_parser* p, const char* data, size_t length) noexcept
			{ return call(p, &Parser::on_url, data, length); }

	static int on_status(http_parser* p, const char* data, size_t length) noexcept
			{ return call(p, &Parser::on_status, data, length); }

	static int on_header_field(http_parser* p, const char* data, size_t length) noexcept
			{ return call(p, &Parser::on_header_field, data, length); }

	static int on_header_value(http_parser* p, const char* data, size_t length) noexcept
			{ return call(p, &Parser::on_header_value, data, length); }

	static int on_headers_complete(http_parser* p) noexcept
			{ return call(p, &Parser::on_headers_complete); }

	static int on_message_complete(http_parser* p) noexcept
			{ return call(p, &Parser::on_message_complete); }

	static int onBody(http_parser* p, const char* data, size_t length) noexcept
			{ return call(p, &Parser::onBody, data, length); }

	static int on_chunk_header(http_parser* p) noexcept
			{ return call(p, &Parser::on_chunk_header); }

	static int on_chunk_complete(http_parser* p) noexcept
			{ return call(p, &Parser::on_chunk_complete); }
};

template<typename Parser>
class parser_settings
{
	http_parser_settings s_;

public:
	static http_parser_settings& get()
	{
		static parser_settings instance;
		return instance.s_;
	}

	parser_settings(const parser_settings&) = delete;
	parser_settings(parser_settings&&)      = delete;

private:
	parser_settings()
	{
		http_parser_settings_init(&s_);
		s_.on_message_begin    = &callbacks<Parser>::on_message_begin;
		s_.on_url              = &callbacks<Parser>::on_url;
		s_.on_status           = &callbacks<Parser>::on_status;
		s_.on_header_field     = &callbacks<Parser>::on_header_field;
		s_.on_header_value     = &callbacks<Parser>::on_header_value;
		s_.on_headers_complete = &callbacks<Parser>::on_headers_complete;
		s_.on_body             = &callbacks<Parser>::onBody;
		s_.on_message_complete = &callbacks<Parser>::on_message_complete;
		s_.on_chunk_header     = &callbacks<Parser>::on_chunk_header;
		s_.on_chunk_complete   = &callbacks<Parser>::on_chunk_complete;
	}
};

struct header_name_less
{
	bool operator()	(const std::string& s1, const std::string& s2) const
			{ return strcasecmp(s1.c_str(), s2.c_str()) < 0; }
};

using headers = std::map<std::string, std::string, detail::header_name_less>;

class header_assembler
{
	headers&    headers_;
	std::string current_header_field_;
	std::string current_header_value_;
	bool        current_header_field_complete_ = false;

public:
	header_assembler(headers& h): headers_(h) {}
	header_assembler(const header_assembler&)            = delete;
	header_assembler(header_assembler&&)                 = delete;
	header_assembler& operator=(const header_assembler&) = delete;
	header_assembler& operator=(header_assembler&&)      = delete;

	void reset()
	{
		current_header_field_.clear();
		current_header_value_.clear();
		current_header_field_complete_ = false;
	}

	void on_header_field(const char* data, std::size_t length)
	{
		if (current_header_field_complete_) {
			on_single_header_complete();
		}
		current_header_field_.append(data, length);
	}

	void on_header_value(const char* data, std::size_t length)
	{
		current_header_value_.append(data, length);
		current_header_field_complete_ = true;
	}

	void on_headers_complete()
	{
		on_single_header_complete();
	}

private:
	void on_single_header_complete()
	{
		if (current_header_field_.empty()) {
			return;
		}
		std::string& header_value = headers_[current_header_field_];
		if (header_value.empty()) {
			header_value.swap(current_header_value_);
		} else if (!current_header_value_.empty()) {
			header_value.reserve(1 + current_header_value_.size());
			header_value.append(",");
			header_value.append(current_header_value_);
		}
		current_header_field_.clear();
		current_header_value_.clear();
		current_header_field_complete_ = false;
	}
};

class LengthLimiter
{
public:
	using OnLimitExceeded =
			std::function<void(std::size_t, std::size_t)>;
private:
	std::size_t currentLength = 0;
	std::size_t maxLength = 0;
	OnLimitExceeded onLimitExceeded;
public:
	LengthLimiter(OnLimitExceeded onLimitExceeded):
			onLimitExceeded(onLimitExceeded) {}
	inline void setMaxLength(std::size_t max) { maxLength = max; }
	inline void checkLength(std::size_t delta)
	{
		currentLength += delta;
		if (maxLength && currentLength > maxLength) {
			onLimitExceeded(currentLength, maxLength);
		}
	}
	inline void reset() { currentLength = 0; }
};

class headers_owner
{
protected:
	headers headers_;

public:
	headers_owner()                                = default;
	headers_owner(const headers_owner&)            = default;
	headers_owner& operator=(const headers_owner&) = default;
	headers_owner(headers_owner&&)                 = default;
	headers_owner& operator=(headers_owner&&)      = default;

	bool has_header(const std::string& headerName) const noexcept
			{ return headers_.count(headerName) > 0U; }

	const std::string& header(const std::string& headerName) const
	{
		headers::const_iterator it = headers_.find(headerName);
		if (headers_.cend() == it) {
			throw header_not_found_error(
					"Request does not have '" + headerName + "' header");
		}
		return it->second;
	}

	const std::string& header(const std::string& headerName,
			const std::string& defaultValue) const noexcept
	{
		headers::const_iterator it = headers_.find(headerName);
		return headers_.cend() == it ? defaultValue : it->second;
	}

	std::size_t header_count() const noexcept { return headers_.size(); }

	const headers& all_headers() const noexcept { return headers_; }
};

template <typename IterT>
struct IsContiguousMemoryForwardIterator : std::is_pointer<IterT> {};

template <>
struct IsContiguousMemoryForwardIterator
		<typename std::vector<char>::iterator> : std::true_type {};
template <>
struct IsContiguousMemoryForwardIterator
		<typename std::vector<char>::const_iterator> : std::true_type {};
template <>
struct IsContiguousMemoryForwardIterator
		<typename std::string::iterator> : std::true_type {};
template <>
struct IsContiguousMemoryForwardIterator
		<typename std::string::const_iterator> : std::true_type {};

#ifdef HTTP_PARSER_CPP_IS_CONTIGUOUS_MEMORY_FORWARD_ITERATOR_EXTRA_SPECIALIZATIONS
HTTP_PARSER_CPP_IS_CONTIGUOUS_MEMORY_FORWARD_ITERATOR_EXTRA_SPECIALIZATIONS
#endif

class ParserBase
{
protected:
	http_parser p;
	http_parser_settings& parser_settings_;
	std::exception_ptr callbackException;
	std::size_t totalConsumedLength = 0;
	protocol_upgrade_handler protocolUpgradeHandler;

public:
	std::string protocolUpgradeData;

protected:
	ParserBase(http_parser_type parserType, http_parser_settings& parserSettings)
		: parser_settings_(parserSettings)
	{
		http_parser_init(&p, parserType);
		p.data = this;
	}

	virtual void throwParseError(const std::string& errorMessage) = 0;

public:
	ParserBase(const ParserBase&) = delete;
	ParserBase& operator=(const ParserBase&) = delete;

	virtual ~ParserBase() {}

	void feed(const char* input, std::size_t inputLength)
	{
		if (p.upgrade) {
			if (protocolUpgradeHandler) {
				protocolUpgradeHandler(input, input + inputLength);
			} else {
				protocolUpgradeData.append(input, inputLength);
			}
		} else {
			std::size_t consumedLength = http_parser_execute(
					&p, &parser_settings_, input, inputLength);
			totalConsumedLength += consumedLength;
			if (callbackException) {
				std::exception_ptr e = nullptr;
				std::swap(e, callbackException);
				std::rethrow_exception(e);
			}
			if (HTTP_PARSER_ERRNO(&p) != HPE_OK || consumedLength > inputLength
					|| (consumedLength < inputLength && !p.upgrade)) {
				std::ostringstream errMsg;
				errMsg << "HTTP Parse error on character " << totalConsumedLength
						<< ": " << http_errno_name(HTTP_PARSER_ERRNO(&p));
				throwParseError(errMsg.str());
			}
			if (p.upgrade) {
				feed(input + consumedLength, inputLength - consumedLength);
			}
		}
	}

	template<typename IterT>
	typename std::enable_if<std::is_same<
			typename std::iterator_traits<IterT>::value_type, char>::value>::type
	feed(IterT begin, IterT end) { feedIter(begin, end); }

	void feedEof() { (void) feed(nullptr, 0); }

private:
	template<typename IterT>
	typename std::enable_if<!IsContiguousMemoryForwardIterator<IterT>::value>::type
	feedIter(IterT begin, IterT end)
	{
		for (IterT it = begin; it != end; ++it) {
			char c = *it;
			feed(&c, 1);
		}
	}

	template<typename IterT>
	typename std::enable_if<IsContiguousMemoryForwardIterator<IterT>::value>::type
	feedIter(IterT begin, IterT end)
	{
		const char* buf = &(*begin);
		const std::size_t len = end - begin;
		feed(buf, len);
	}
};

} /* namespace detail */

struct HttpVersion
{
	unsigned short major = 0;
	unsigned short minor = 0;
public:
	std::string toString() const
	{
		std::string ret;
		ret.reserve(3);
		char buf[12];
		(void) std::snprintf(buf, sizeof(buf), "%u", major);
		ret.append(buf);
		ret.append(".");
		(void) std::snprintf(buf, sizeof(buf), "%u", minor);
		ret.append(buf);
		return ret;
	}
};

struct RequestHead : detail::headers_owner
{
	friend class BigRequestParser;
	using RequestType = enum http_method;
public:
	RequestType type = HTTP_HEAD;
	HttpVersion httpVersion;
	std::string url;
	bool keepAlive = false;
};

struct Request : private RequestHead
{
	friend class RequestParser;
	using RequestHead::type;
	using RequestHead::httpVersion;
	using RequestHead::url;
	using RequestHead::keepAlive;
	std::string body;
public:
	using RequestHead::has_header;
	using RequestHead::header;
	using RequestHead::header_count;
	using RequestHead::all_headers;
	RequestHead& getHead() noexcept { return *this; }
};

struct ResponseHead : detail::headers_owner
{
	friend class BigResponseParser;
	unsigned statusCode = 0;
	std::string statusText;
	HttpVersion httpVersion;
	bool keepAlive = false;
};

struct Response : private ResponseHead
{
	friend class ResponseParser;
	using ResponseHead::statusCode;
	using ResponseHead::statusText;
	using ResponseHead::httpVersion;
	using ResponseHead::keepAlive;
	std::string body;
public:
	using ResponseHead::has_header;
	using ResponseHead::header;
	using ResponseHead::header_count;
	using ResponseHead::all_headers;
	ResponseHead& getHead() noexcept { return *this; }
};

using RequestConsumer = std::function<void(Request&&)>;
using ResponseConsumer = std::function<void(Response&&)>;

class RequestParser : public detail::ParserBase
{
	Request currentRequest;
	detail::header_assembler header_assembler_;
	RequestConsumer requestConsumer;
	detail::LengthLimiter requestLengthLimiter
	{
		[](std::size_t, std::size_t limit)
		{
			throw request_too_big("Request exceeded size limit of "
					+ std::to_string(limit));
		}
	};

public:
	std::deque<Request> parsedRequests;

public:
	RequestParser()
		: ParserBase(HTTP_REQUEST, detail::parser_settings<RequestParser>::get()),
			header_assembler_(currentRequest.headers_) {}

	RequestParser(RequestConsumer requestConsumer)
		: ParserBase(HTTP_REQUEST, detail::parser_settings<RequestParser>::get()),
			header_assembler_(currentRequest.headers_), requestConsumer(requestConsumer) {}

	RequestParser(protocol_upgrade_handler protocolUpgradeHandler)
		: ParserBase(HTTP_REQUEST, detail::parser_settings<RequestParser>::get()),
			header_assembler_(currentRequest.headers_)
	{
		this->protocolUpgradeHandler = protocolUpgradeHandler;
	}

	RequestParser(RequestConsumer requestConsumer,
			protocol_upgrade_handler protocolUpgradeHandler)
		: ParserBase(HTTP_REQUEST, detail::parser_settings<RequestParser>::get()),
			header_assembler_(currentRequest.headers_), requestConsumer(requestConsumer)
	{
		this->protocolUpgradeHandler = protocolUpgradeHandler;
	}

	void setMaxRequestLength(std::size_t maxLength) // 0 means unlimited
			{ requestLengthLimiter.setMaxLength(maxLength); }

private:
	void throwParseError(const std::string& errorMessage) override
			{ throw request_parse_error(errorMessage); }

private:
	friend struct detail::callbacks<RequestParser>;

	int on_message_begin()
	{
		currentRequest = Request();
		header_assembler_.reset();
		requestLengthLimiter.reset();
		return 0;
	}

	int on_url(const char* data, std::size_t length)
	{
		requestLengthLimiter.checkLength(length);
		currentRequest.url.append(data, length);
		return 0;
	}

	int on_status(const char* data, std::size_t length)
	{
		assert(false); // not reached
		return 0;
	}

	int on_header_field(const char* data, std::size_t length)
	{
		requestLengthLimiter.checkLength(length);
		header_assembler_.on_header_field(data, length);
		return 0;
	}

	int on_header_value(const char* data, std::size_t length)
	{
		requestLengthLimiter.checkLength(length);
		header_assembler_.on_header_value(data, length);
		return 0;
	}

	int on_headers_complete()
	{
		header_assembler_.on_headers_complete();
		return 0;
	}

	int onBody(const char* data, std::size_t length)
	{
		requestLengthLimiter.checkLength(length);
		currentRequest.body.append(data, length);
		return 0;
	}

	int on_message_complete()
	{
		currentRequest.type = static_cast<RequestHead::RequestType>(p.method);
		currentRequest.httpVersion.major = p.http_major;
		currentRequest.httpVersion.minor = p.http_minor;
		currentRequest.keepAlive = (http_should_keep_alive(&p) != 0);
		if (requestConsumer) {
			requestConsumer(std::move(currentRequest));
		} else {
			parsedRequests.push_back(std::move(currentRequest));
		}
		return 0;
	}

	int on_chunk_header()
	{
		header_assembler_.reset();
		return 0;
	}

	int on_chunk_complete()
	{
		header_assembler_.on_headers_complete();
		return 0;
	}
};

class ResponseParser : public detail::ParserBase
{
	Response currentResponse;
	detail::header_assembler header_assembler_;
	ResponseConsumer responseConsumer;
	detail::LengthLimiter responseLengthLimiter
	{
		[](std::size_t, std::size_t limit)
		{
			throw response_too_big("Response exceeded size limit of "
					+ std::to_string(limit));
		}
	};

public:
	std::deque<Response> parsedResponses;

public:
	ResponseParser()
		: ParserBase(HTTP_RESPONSE, detail::parser_settings<ResponseParser>::get()),
			header_assembler_(currentResponse.headers_) {}

	ResponseParser(ResponseConsumer responseConsumer)
		: ParserBase(HTTP_RESPONSE, detail::parser_settings<ResponseParser>::get()),
			header_assembler_(currentResponse.headers_),
			responseConsumer(responseConsumer) {}

	ResponseParser(protocol_upgrade_handler protocolUpgradeHandler)
		: ParserBase(HTTP_RESPONSE, detail::parser_settings<ResponseParser>::get()),
			header_assembler_(currentResponse.headers_)
	{
		this->protocolUpgradeHandler = protocolUpgradeHandler;
	}

	ResponseParser(ResponseConsumer responseConsumer,
			protocol_upgrade_handler protocolUpgradeHandler)
		: ParserBase(HTTP_RESPONSE, detail::parser_settings<ResponseParser>::get()),
			header_assembler_(currentResponse.headers_),
			responseConsumer(responseConsumer)
	{
		this->protocolUpgradeHandler = protocolUpgradeHandler;
	}

	void setMaxResponseLength(std::size_t maxLength) // 0 means unlimited
			{ responseLengthLimiter.setMaxLength(maxLength); }

private:
	void throwParseError(const std::string& errorMessage) override
			{ throw response_parse_error(errorMessage); }

private:
	friend struct detail::callbacks<ResponseParser>;

	int on_message_begin()
	{
		currentResponse = Response();
		header_assembler_.reset();
		responseLengthLimiter.reset();
		return 0;
	}

	int on_url(const char* data, std::size_t length)
	{
		(void) data;
		(void) length;
		assert(false); // not reached
		return 0;
	}

	int on_status(const char* data, std::size_t length)
	{
		currentResponse.statusText.append(data, length);
		return 0;
	}

	int on_header_field(const char* data, std::size_t length)
	{
		responseLengthLimiter.checkLength(length);
		header_assembler_.on_header_field(data, length);
		return 0;
	}

	int on_header_value(const char* data, std::size_t length)
	{
		responseLengthLimiter.checkLength(length);
		header_assembler_.on_header_value(data, length);
		return 0;
	}

	int on_headers_complete()
	{
		header_assembler_.on_headers_complete();
		return 0;
	}

	int onBody(const char* data, std::size_t length)
	{
		responseLengthLimiter.checkLength(length);
		currentResponse.body.append(data, length);
		return 0;
	}

	int on_message_complete()
	{
		currentResponse.statusCode = p.status_code;
		currentResponse.httpVersion.major = p.http_major;
		currentResponse.httpVersion.minor = p.http_minor;
		currentResponse.keepAlive = (http_should_keep_alive(&p) != 0);
		if (responseConsumer) {
			responseConsumer(std::move(currentResponse));
		} else {
			parsedResponses.push_back(std::move(currentResponse));
		}
		return 0;
	}

	int on_chunk_header()
	{
		header_assembler_.reset();
		return 0;
	}

	int on_chunk_complete()
	{
		header_assembler_.on_headers_complete();
		return 0;
	}
};

using BigRequestCallback = std::function<void(const RequestHead &requestHead,
		const char *bodyPart, std::size_t bodyPartLength, bool finished)>;

class BigRequestParser : public detail::ParserBase
{
	RequestHead currentRequest;
	detail::header_assembler header_assembler_ { currentRequest.headers_ };
	BigRequestCallback requestCallback;
	detail::LengthLimiter headersLengthLimiter
	{
		[](std::size_t, std::size_t limit)
		{
			throw request_headers_too_big("Request headers exceeded size limit of "
					+ std::to_string(limit));
		}
	};

public:
	BigRequestParser(BigRequestCallback requestCallback,
			protocol_upgrade_handler protocolUpgradeHandler = nullptr)
		: ParserBase(HTTP_REQUEST, detail::parser_settings<BigRequestParser>::get()),
			requestCallback(requestCallback)
	{
		this->protocolUpgradeHandler = protocolUpgradeHandler;
	}

	void setMaxHeadersLength(std::size_t maxLength) // 0 means unlimited
			{ headersLengthLimiter.setMaxLength(maxLength); }

private:
	void throwParseError(const std::string& errorMessage) override
			{ throw request_parse_error(errorMessage); }

private:
	friend struct detail::callbacks<BigRequestParser>;

	int on_message_begin()
	{
		currentRequest = RequestHead();
		header_assembler_.reset();
		headersLengthLimiter.reset();
		return 0;
	}

	int on_url(const char* data, std::size_t length)
	{
		headersLengthLimiter.checkLength(length);
		currentRequest.url.append(data, length);
		return 0;
	}

	int on_status(const char* data, std::size_t length)
	{
		assert(false); // not reached
		return 0;
	}

	int on_header_field(const char* data, std::size_t length)
	{
		headersLengthLimiter.checkLength(length);
		header_assembler_.on_header_field(data, length);
		return 0;
	}

	int on_header_value(const char* data, std::size_t length)
	{
		headersLengthLimiter.checkLength(length);
		header_assembler_.on_header_value(data, length);
		return 0;
	}

	int on_headers_complete()
	{
		header_assembler_.on_headers_complete();
		currentRequest.type = static_cast<RequestHead::RequestType>(p.method);
		currentRequest.httpVersion.major = p.http_major;
		currentRequest.httpVersion.minor = p.http_minor;
		currentRequest.keepAlive = (http_should_keep_alive(&p) != 0);
		return 0;
	}

	int onBody(const char* data, std::size_t length)
	{
		requestCallback(currentRequest, data, length, false);
		return 0;
	}

	int on_message_complete()
	{
		requestCallback(currentRequest, nullptr, 0, true);
		return 0;
	}

	int on_chunk_header()
	{
		header_assembler_.reset();
		return 0;
	}

	int on_chunk_complete()
	{
		header_assembler_.on_headers_complete();
		return 0;
	}
};

using BigResponseCallback = std::function<void(const ResponseHead &responseHead,
		const char *bodyPart, std::size_t bodyPartLength, bool finished)>;

class BigResponseParser : public detail::ParserBase
{
	ResponseHead currentResponse;
	detail::header_assembler header_assembler_ { currentResponse.headers_ };
	BigResponseCallback responseCallback;
	detail::LengthLimiter headersLengthLimiter
	{
		[](std::size_t, std::size_t limit)
		{
			throw response_headers_too_big("Response headers exceeded size limit of "
					+ std::to_string(limit));
		}
	};

public:
	BigResponseParser(BigResponseCallback responseCallback,
			protocol_upgrade_handler protocolUpgradeHandler = nullptr)
		: ParserBase(HTTP_RESPONSE,
					detail::parser_settings<BigResponseParser>::get()),
			responseCallback(responseCallback)
	{
		this->protocolUpgradeHandler = protocolUpgradeHandler;
	}

	void setMaxHeadersLength(std::size_t maxLength) // 0 means unlimited
			{ headersLengthLimiter.setMaxLength(maxLength); }

private:
	void throwParseError(const std::string& errorMessage) override
			{ throw response_parse_error(errorMessage); }

private:
	friend struct detail::callbacks<BigResponseParser>;

	int on_message_begin()
	{
		currentResponse = ResponseHead();
		header_assembler_.reset();
		headersLengthLimiter.reset();
		return 0;
	}

	int on_url(const char* data, std::size_t length)
	{
		(void) data;
		(void) length;
		assert(false); // not reached
		return 0;
	}

	int on_status(const char* data, std::size_t length)
	{
		headersLengthLimiter.checkLength(length);
		currentResponse.statusText.append(data, length);
		return 0;
	}

	int on_header_field(const char* data, std::size_t length)
	{
		headersLengthLimiter.checkLength(length);
		header_assembler_.on_header_field(data, length);
		return 0;
	}

	int on_header_value(const char* data, std::size_t length)
	{
		headersLengthLimiter.checkLength(length);
		header_assembler_.on_header_value(data, length);
		return 0;
	}

	int on_headers_complete()
	{
		header_assembler_.on_headers_complete();
		currentResponse.statusCode = p.status_code;
		currentResponse.httpVersion.major = p.http_major;
		currentResponse.httpVersion.minor = p.http_minor;
		currentResponse.keepAlive = (http_should_keep_alive(&p) != 0);
		return 0;
	}

	int onBody(const char* data, std::size_t length)
	{
		responseCallback(currentResponse, data, length, false);
		return 0;
	}

	int on_message_complete()
	{
		responseCallback(currentResponse, nullptr, 0, true);
		return 0;
	}

	int on_chunk_header()
	{
		header_assembler_.reset();
		return 0;
	}

	int on_chunk_complete()
	{
		header_assembler_.on_headers_complete();
		return 0;
	}
};

struct Url
{
	std::string schema;
	std::string host;
	std::string path;
	std::string query;
	std::string fragment;
	std::string userinfo;
	unsigned    port = 0;
};

Url parseUrl(const std::string& input, bool isConnect = false)
{
	http_parser_url u;
	http_parser_url_init(&u);
	int err = http_parser_parse_url(
			input.c_str(), input.size(), int(isConnect), &u);
	if (err) {
		throw url_parse_error("Failed to parse this url: '" + input + "'");
	}

	Url parsedUrl;

	using FieldDef = std::pair<http_parser_url_fields, std::string Url::*>;
	static const FieldDef stringFields[] = {
		{ UF_SCHEMA, &Url::schema },
		{ UF_HOST, &Url::host },
		{ UF_PATH, &Url::path },
		{ UF_QUERY, &Url::query },
		{ UF_FRAGMENT, &Url::fragment },
		{ UF_USERINFO, &Url::userinfo }
	};
	for (const FieldDef& field : stringFields) {
		if (u.field_set & (1 << field.first)) {
			parsedUrl.*field.second = input.substr(
					u.field_data[field.first].off, u.field_data[field.first].len);
		}
	}

	if (u.field_set & (1 << UF_PORT)) {
		parsedUrl.port = std::stoul(input.substr(
				u.field_data[UF_PORT].off, u.field_data[UF_PORT].len
		));
	}

	return parsedUrl;
}

using detail::headers;

} /* namespace http */

template<typename StreamT>
StreamT& operator<<(StreamT& stream, const http::HttpVersion& ver)
{
	stream << ver.toString();
	return stream;
}

template<typename StreamT>
StreamT& operator<<(StreamT& stream, http::RequestHead::RequestType reqType)
{
	stream << http_method_str(reqType);
	return stream;
}

template<typename StreamT>
StreamT& operator<<(StreamT& stream, const http::Request& req)
{
	stream << "HTTP/" << req.httpVersion << " " << req.type << " request.\n"
			<< "\tUrl: '" << req.url << "'\n"
			<< "\tHeaders:\n";
	for (const auto& fvPair : req.headers_) {
		stream << "\t\t'" << fvPair.first << "': '" << fvPair.second << "'\n";
	}
	stream << "\tBody is " << req.body.size() << " bytes long.\n\tKeepAlive: "
			<< (req.keepAlive ? "yes" : "no") << ".";
	return stream;
}

template<typename StreamT>
StreamT& operator<<(StreamT& stream, const http::Response& resp)
{
	stream << "HTTP/" << resp.httpVersion << " '" << resp.statusCode << "' "
			<< resp.statusText << " response.\n"
			<< "\tHeaders:\n";
	for (const auto& fvPair : resp.headers_) {
		stream << "\t\t'" << fvPair.first << "': '" << fvPair.second << "'\n";
	}
	stream << "\tBody is " << resp.body.size() << " bytes long.\n\tKeepAlive: "
			<< (resp.keepAlive ? "yes" : "no") << ".";
	return stream;
}

template<typename StreamT>
StreamT& operator<<(StreamT& stream, const http::Url& url)
{
	stream << "URL\n"
			<< "schema: '" << url.schema << "'\n"
			<< "host: '" << url.host << "'\n"
			<< "port: " << url.port << "\n"
			<< "path: '" << url.path << "'\n"
			<< "query: '" << url.query << "'\n"
			<< "fragment: '" << url.fragment << "'\n"
			<< "userinfo: '" << url.userinfo << "'\n";
	return stream;
}
