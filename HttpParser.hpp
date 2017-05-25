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

namespace detail {

struct HeaderNameLess
{
	bool operator()	(const std::string& s1, const std::string& s2) const
			{ return strcasecmp(s1.c_str(), s2.c_str()) < 0; }
};

} /* namespace detail */

using Headers = std::map<std::string, std::string, detail::HeaderNameLess>;

using ProtocolUpgradeHandler =
		std::function<void(const char* begin, const char* end)>;

class ParseError: public std::runtime_error
{
public:
	using runtime_error::runtime_error;
};

class TooBigError: public std::runtime_error
{
public:
	using runtime_error::runtime_error;
};

class RequestParseError: public ParseError
{
public:
	using ParseError::ParseError;
};

class ResponseParseError: public ParseError
{
public:
	using ParseError::ParseError;
};

class RequestTooBig: public TooBigError
{
public:
	using TooBigError::TooBigError;
};

class RequestHeadersTooBig: public TooBigError
{
public:
	using TooBigError::TooBigError;
};

class ResponseTooBig: public TooBigError
{
public:
	using TooBigError::TooBigError;
};

class ResponseHeadersTooBig: public TooBigError
{
public:
	using TooBigError::TooBigError;
};

class UrlParseError: public ParseError
{
public:
	using ParseError::ParseError;
};

class HeaderNotFoundError: public std::runtime_error
{
public:
	using runtime_error::runtime_error;
};

namespace detail {

template<typename ParserT>
struct Callbacks
{
	static int onMessageBegin(http_parser* p) noexcept
	{
		try {
			return ((ParserT*) p->data)->onMessageBegin();
		} catch (...) {
			((ParserT*) p->data)->callbackException = std::current_exception();
		}
		return -1;
	}

	static int onUrl(http_parser* p, const char* data, size_t length) noexcept
	{
		try {
			return ((ParserT*) p->data)->onUrl(data, length);
		} catch (...) {
			((ParserT*) p->data)->callbackException = std::current_exception();
		}
		return -1;
	}

	static int onStatus(http_parser* p, const char* data, size_t length) noexcept
	{
		try {
			return ((ParserT*) p->data)->onStatus(data, length);
		} catch (...) {
			((ParserT*) p->data)->callbackException = std::current_exception();
		}
		return -1;
	}

	static int onHeaderField(http_parser* p, const char* data, size_t length)
			 noexcept
	{
		try {
			return ((ParserT*) p->data)->onHeaderField(data, length);
		} catch (...) {
			((ParserT*) p->data)->callbackException = std::current_exception();
		}
		return -1;
	}

	static int onHeaderValue(http_parser* p, const char* data, size_t length)
			noexcept
	{
		try {
			return ((ParserT*) p->data)->onHeaderValue(data, length);
		} catch (...) {
			((ParserT*) p->data)->callbackException = std::current_exception();
		}
		return -1;
	}

	static int onHeadersComplete(http_parser* p) noexcept
	{
		try {
			return ((ParserT*) p->data)->onHeadersComplete();
		} catch (...) {
			((ParserT*) p->data)->callbackException = std::current_exception();
		}
		return -1;
	}

	static int onMessageComplete(http_parser* p) noexcept
	{
		try {
			return ((ParserT*) p->data)->onMessageComplete();
		} catch (...) {
			((ParserT*) p->data)->callbackException = std::current_exception();
		}
		return -1;
	}

	static int onBody(http_parser* p, const char* data, size_t length) noexcept
	{
		try {
			return ((ParserT*) p->data)->onBody(data, length);
		} catch (...) {
			((ParserT*) p->data)->callbackException = std::current_exception();
		}
		return -1;
	}

	static int onChunkHeader(http_parser* p) noexcept
	{
		try {
			return ((ParserT*) p->data)->onChunkHeader();
		} catch (...) {
			((ParserT*) p->data)->callbackException = std::current_exception();
		}
		return -1;
	}

	static int onChunkComplete(http_parser* p) noexcept
	{
		try {
			return ((ParserT*) p->data)->onChunkComplete();
		} catch (...) {
			((ParserT*) p->data)->callbackException = std::current_exception();
		}
		return -1;
	}
};

template<typename ParserT>
struct ParserSettings
{
	http_parser_settings s;

public:
	static ParserSettings& get()
	{
		static ParserSettings instance;
		return instance;
	}

	ParserSettings(const ParserSettings&) = delete;
	ParserSettings(ParserSettings&&) = delete;

private:
	ParserSettings()
	{
		http_parser_settings_init(&s);
		s.on_message_begin = &Callbacks<ParserT>::onMessageBegin;
		s.on_url = &Callbacks<ParserT>::onUrl;
		s.on_status = &Callbacks<ParserT>::onStatus;
		s.on_header_field = &Callbacks<ParserT>::onHeaderField;
		s.on_header_value = &Callbacks<ParserT>::onHeaderValue;
		s.on_headers_complete = &Callbacks<ParserT>::onHeadersComplete;
		s.on_body = &Callbacks<ParserT>::onBody;
		s.on_message_complete = &Callbacks<ParserT>::onMessageComplete;
		s.on_chunk_header = &Callbacks<ParserT>::onChunkHeader;
		s.on_chunk_complete = &Callbacks<ParserT>::onChunkComplete;
	}
};

class HeaderAssembler
{
	Headers& headers;
	std::string currentHeaderField;
	std::string currentHeaderValue;
	bool currentHeaderFieldComplete = false;

public:
	HeaderAssembler(Headers& headers): headers(headers) {}
	HeaderAssembler(const HeaderAssembler&) = delete;
	HeaderAssembler(HeaderAssembler&&) = delete;
	HeaderAssembler& operator=(const HeaderAssembler&) = delete;
	HeaderAssembler& operator=(HeaderAssembler&&) = delete;

	void reset()
	{
		currentHeaderField.clear();
		currentHeaderValue.clear();
		currentHeaderFieldComplete = false;
	}

	void onHeaderField(const char* data, std::size_t length)
	{
		if (currentHeaderFieldComplete) {
			onSingleHeaderComplete();
		}
		currentHeaderField.append(data, length);
	}

	void onHeaderValue(const char* data, std::size_t length)
	{
		currentHeaderValue.append(data, length);
		currentHeaderFieldComplete = true;
	}

	void onHeadersComplete()
	{
		onSingleHeaderComplete();
	}

private:
	void onSingleHeaderComplete()
	{
		if (currentHeaderField.empty()) {
			return;
		}
		std::string& headerValue = headers[currentHeaderField];
		if (headerValue.empty()) {
			headerValue.swap(currentHeaderValue);
		} else if (!currentHeaderValue.empty()) {
			headerValue.reserve(1 + currentHeaderValue.size());
			headerValue.append(",");
			headerValue.append(currentHeaderValue);
		}
		currentHeaderField.clear();
		currentHeaderValue.clear();
		currentHeaderFieldComplete = false;
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

struct ConvenientHeaders // use this class as a mixin in Request and Response
{
	Headers headers;
public:
	bool hasHeader(const std::string& headerName) const noexcept
			{ return headers.count(headerName) > 0U; }
	const std::string& getHeader(const std::string& headerName) const
	{
		Headers::const_iterator it = headers.find(headerName);
		if (headers.cend() == it) {
			throw HeaderNotFoundError(
					"Request does not have '" + headerName + "' header");
		}
		return it->second;
	}
	const std::string& getHeader(const std::string& headerName,
			const std::string& defaultValue) const noexcept
	{
		Headers::const_iterator it = headers.find(headerName);
		return headers.cend() == it ? defaultValue : it->second;
	}
};

template <typename IterT>
struct IsContiguousMemoryForwardIterator: std::is_pointer<IterT> {};

template <>
struct IsContiguousMemoryForwardIterator
		<typename std::vector<char>::iterator>: std::true_type {};
template <>
struct IsContiguousMemoryForwardIterator
		<typename std::vector<char>::const_iterator>: std::true_type {};
template <>
struct IsContiguousMemoryForwardIterator
		<typename std::string::iterator>: std::true_type {};
template <>
struct IsContiguousMemoryForwardIterator
		<typename std::string::const_iterator>: std::true_type {};

#ifdef HTTP_PARSER_CPP_IS_CONTIGUOUS_MEMORY_FORWARD_ITERATOR_EXTRA_SPECIALIZATIONS
HTTP_PARSER_CPP_IS_CONTIGUOUS_MEMORY_FORWARD_ITERATOR_EXTRA_SPECIALIZATIONS
#endif

class ParserBase
{
protected:
	http_parser p;
	http_parser_settings& parserSettings;
	std::exception_ptr callbackException;
	std::size_t totalConsumedLength = 0;
	ProtocolUpgradeHandler protocolUpgradeHandler;

public:
	std::string protocolUpgradeData;

protected:
	ParserBase(http_parser_type parserType, http_parser_settings& parserSettings)
		: parserSettings(parserSettings)
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
					&p, &parserSettings, input, inputLength);
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

struct Request: detail::ConvenientHeaders
{
	using Type = enum http_method;
public:
	Type type = HTTP_HEAD;
	HttpVersion httpVersion;
	std::string url;
	std::string body;
	bool keepAlive = false;
};

struct Response: detail::ConvenientHeaders
{
	unsigned statusCode = 0;
	std::string statusText;
	HttpVersion httpVersion;
	std::string body;
	bool keepAlive = false;
};

using RequestConsumer = std::function<void(Request&&)>;
using ResponseConsumer = std::function<void(Response&&)>;

class RequestParser: public detail::ParserBase
{
	Request currentRequest;
	detail::HeaderAssembler headerAssembler;
	RequestConsumer requestConsumer;
	detail::LengthLimiter requestLengthLimiter
	{
		[](std::size_t, std::size_t limit)
		{
			throw RequestTooBig("Request exceeded size limit of "
					+ std::to_string(limit));
		}
	};

public:
	std::deque<Request> parsedRequests;

public:
	RequestParser()
		: ParserBase(HTTP_REQUEST, detail::ParserSettings<RequestParser>::get().s),
			headerAssembler(currentRequest.headers) {}

	RequestParser(RequestConsumer requestConsumer)
		: ParserBase(HTTP_REQUEST, detail::ParserSettings<RequestParser>::get().s),
			headerAssembler(currentRequest.headers), requestConsumer(requestConsumer) {}

	RequestParser(ProtocolUpgradeHandler protocolUpgradeHandler)
		: ParserBase(HTTP_REQUEST, detail::ParserSettings<RequestParser>::get().s),
			headerAssembler(currentRequest.headers)
	{
		this->protocolUpgradeHandler = protocolUpgradeHandler;
	}

	RequestParser(RequestConsumer requestConsumer,
			ProtocolUpgradeHandler protocolUpgradeHandler)
		: ParserBase(HTTP_REQUEST, detail::ParserSettings<RequestParser>::get().s),
			headerAssembler(currentRequest.headers), requestConsumer(requestConsumer)
	{
		this->protocolUpgradeHandler = protocolUpgradeHandler;
	}

	void setMaxRequestLength(std::size_t maxLength) // 0 means unlimited
			{ requestLengthLimiter.setMaxLength(maxLength); }

private:
	void throwParseError(const std::string& errorMessage) override
			{ throw RequestParseError(errorMessage); }

private:
	friend struct detail::Callbacks<RequestParser>;

	int onMessageBegin()
	{
		currentRequest = Request();
		headerAssembler.reset();
		requestLengthLimiter.reset();
		return 0;
	}

	int onUrl(const char* data, std::size_t length)
	{
		requestLengthLimiter.checkLength(length);
		currentRequest.url.append(data, length);
		return 0;
	}

	int onStatus(const char* data, std::size_t length)
	{
		assert(false); // not reached
		return 0;
	}

	int onHeaderField(const char* data, std::size_t length)
	{
		requestLengthLimiter.checkLength(length);
		headerAssembler.onHeaderField(data, length);
		return 0;
	}

	int onHeaderValue(const char* data, std::size_t length)
	{
		requestLengthLimiter.checkLength(length);
		headerAssembler.onHeaderValue(data, length);
		return 0;
	}

	int onHeadersComplete()
	{
		headerAssembler.onHeadersComplete();
		return 0;
	}

	int onBody(const char* data, std::size_t length)
	{
		requestLengthLimiter.checkLength(length);
		currentRequest.body.append(data, length);
		return 0;
	}

	int onMessageComplete()
	{
		currentRequest.type = static_cast<Request::Type>(p.method);
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

	int onChunkHeader()
	{
		headerAssembler.reset();
		return 0;
	}

	int onChunkComplete()
	{
		headerAssembler.onHeadersComplete();
		return 0;
	}
};

class ResponseParser: public detail::ParserBase
{
	Response currentResponse;
	detail::HeaderAssembler headerAssembler;
	ResponseConsumer responseConsumer;
	detail::LengthLimiter responseLengthLimiter
	{
		[](std::size_t, std::size_t limit)
		{
			throw ResponseTooBig("Response exceeded size limit of "
					+ std::to_string(limit));
		}
	};

public:
	std::deque<Response> parsedResponses;

public:
	ResponseParser()
		: ParserBase(HTTP_RESPONSE, detail::ParserSettings<ResponseParser>::get().s),
			headerAssembler(currentResponse.headers) {}

	ResponseParser(ResponseConsumer responseConsumer)
		: ParserBase(HTTP_RESPONSE, detail::ParserSettings<ResponseParser>::get().s),
			headerAssembler(currentResponse.headers),
			responseConsumer(responseConsumer) {}

	ResponseParser(ProtocolUpgradeHandler protocolUpgradeHandler)
		: ParserBase(HTTP_RESPONSE, detail::ParserSettings<ResponseParser>::get().s),
			headerAssembler(currentResponse.headers)
	{
		this->protocolUpgradeHandler = protocolUpgradeHandler;
	}

	ResponseParser(ResponseConsumer responseConsumer,
			ProtocolUpgradeHandler protocolUpgradeHandler)
		: ParserBase(HTTP_RESPONSE, detail::ParserSettings<ResponseParser>::get().s),
			headerAssembler(currentResponse.headers),
			responseConsumer(responseConsumer)
	{
		this->protocolUpgradeHandler = protocolUpgradeHandler;
	}

	void setMaxResponseLength(std::size_t maxLength) // 0 means unlimited
			{ responseLengthLimiter.setMaxLength(maxLength); }

private:
	void throwParseError(const std::string& errorMessage) override
			{ throw ResponseParseError(errorMessage); }

private:
	friend struct detail::Callbacks<ResponseParser>;

	int onMessageBegin()
	{
		currentResponse = Response();
		headerAssembler.reset();
		responseLengthLimiter.reset();
		return 0;
	}

	int onUrl(const char* data, std::size_t length)
	{
		(void) data;
		(void) length;
		assert(false); // not reached
		return 0;
	}

	int onStatus(const char* data, std::size_t length)
	{
		currentResponse.statusText.append(data, length);
		return 0;
	}

	int onHeaderField(const char* data, std::size_t length)
	{
		responseLengthLimiter.checkLength(length);
		headerAssembler.onHeaderField(data, length);
		return 0;
	}

	int onHeaderValue(const char* data, std::size_t length)
	{
		responseLengthLimiter.checkLength(length);
		headerAssembler.onHeaderValue(data, length);
		return 0;
	}

	int onHeadersComplete()
	{
		headerAssembler.onHeadersComplete();
		return 0;
	}

	int onBody(const char* data, std::size_t length)
	{
		responseLengthLimiter.checkLength(length);
		currentResponse.body.append(data, length);
		return 0;
	}

	int onMessageComplete()
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

	int onChunkHeader()
	{
		headerAssembler.reset();
		return 0;
	}

	int onChunkComplete()
	{
		headerAssembler.onHeadersComplete();
		return 0;
	}
};

using BigRequestCallback = std::function<void(const Request &request,
		const char *bodyPart, std::size_t bodyPartLength, bool finished)>;

class BigRequestParser: public detail::ParserBase
{
	Request currentRequest;
	detail::HeaderAssembler headerAssembler { currentRequest.headers };
	BigRequestCallback requestCallback;
	detail::LengthLimiter headersLengthLimiter
	{
		[](std::size_t, std::size_t limit)
		{
			throw RequestHeadersTooBig("Request headers exceeded size limit of "
					+ std::to_string(limit));
		}
	};

public:
	BigRequestParser(BigRequestCallback requestCallback,
			ProtocolUpgradeHandler protocolUpgradeHandler = nullptr)
		: ParserBase(HTTP_REQUEST,
					detail::ParserSettings<BigRequestParser>::get().s),
			requestCallback(requestCallback)
	{
		this->protocolUpgradeHandler = protocolUpgradeHandler;
	}

	void setMaxHeadersLength(std::size_t maxLength) // 0 means unlimited
			{ headersLengthLimiter.setMaxLength(maxLength); }

private:
	void throwParseError(const std::string& errorMessage) override
			{ throw RequestParseError(errorMessage); }

private:
	friend struct detail::Callbacks<BigRequestParser>;

	int onMessageBegin()
	{
		currentRequest = Request();
		headerAssembler.reset();
		headersLengthLimiter.reset();
		return 0;
	}

	int onUrl(const char* data, std::size_t length)
	{
		headersLengthLimiter.checkLength(length);
		currentRequest.url.append(data, length);
		return 0;
	}

	int onStatus(const char* data, std::size_t length)
	{
		assert(false); // not reached
		return 0;
	}

	int onHeaderField(const char* data, std::size_t length)
	{
		headersLengthLimiter.checkLength(length);
		headerAssembler.onHeaderField(data, length);
		return 0;
	}

	int onHeaderValue(const char* data, std::size_t length)
	{
		headersLengthLimiter.checkLength(length);
		headerAssembler.onHeaderValue(data, length);
		return 0;
	}

	int onHeadersComplete()
	{
		headerAssembler.onHeadersComplete();
		currentRequest.type = static_cast<Request::Type>(p.method);
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

	int onMessageComplete()
	{
		requestCallback(currentRequest, nullptr, 0, true);
		return 0;
	}

	int onChunkHeader()
	{
		headerAssembler.reset();
		return 0;
	}

	int onChunkComplete()
	{
		headerAssembler.onHeadersComplete();
		return 0;
	}
};

using BigResponseCallback = std::function<void(const Response &response,
		const char *bodyPart, std::size_t bodyPartLength, bool finished)>;

class BigResponseParser: public detail::ParserBase
{
	Response currentResponse;
	detail::HeaderAssembler headerAssembler { currentResponse.headers };
	BigResponseCallback responseCallback;
	detail::LengthLimiter headersLengthLimiter
	{
		[](std::size_t, std::size_t limit)
		{
			throw ResponseHeadersTooBig("Response headers exceeded size limit of "
					+ std::to_string(limit));
		}
	};

public:
	BigResponseParser(BigResponseCallback responseCallback,
			ProtocolUpgradeHandler protocolUpgradeHandler = nullptr)
		: ParserBase(HTTP_RESPONSE,
					detail::ParserSettings<BigResponseParser>::get().s),
			responseCallback(responseCallback)
	{
		this->protocolUpgradeHandler = protocolUpgradeHandler;
	}

	void setMaxHeadersLength(std::size_t maxLength) // 0 means unlimited
			{ headersLengthLimiter.setMaxLength(maxLength); }

private:
	void throwParseError(const std::string& errorMessage) override
			{ throw ResponseParseError(errorMessage); }

private:
	friend struct detail::Callbacks<BigResponseParser>;

	int onMessageBegin()
	{
		currentResponse = Response();
		headerAssembler.reset();
		headersLengthLimiter.reset();
		return 0;
	}

	int onUrl(const char* data, std::size_t length)
	{
		(void) data;
		(void) length;
		assert(false); // not reached
		return 0;
	}

	int onStatus(const char* data, std::size_t length)
	{
		headersLengthLimiter.checkLength(length);
		currentResponse.statusText.append(data, length);
		return 0;
	}

	int onHeaderField(const char* data, std::size_t length)
	{
		headersLengthLimiter.checkLength(length);
		headerAssembler.onHeaderField(data, length);
		return 0;
	}

	int onHeaderValue(const char* data, std::size_t length)
	{
		headersLengthLimiter.checkLength(length);
		headerAssembler.onHeaderValue(data, length);
		return 0;
	}

	int onHeadersComplete()
	{
		headerAssembler.onHeadersComplete();
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

	int onMessageComplete()
	{
		responseCallback(currentResponse, nullptr, 0, true);
		return 0;
	}

	int onChunkHeader()
	{
		headerAssembler.reset();
		return 0;
	}

	int onChunkComplete()
	{
		headerAssembler.onHeadersComplete();
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
	unsigned port = 0;
};

Url parseUrl(const std::string& input, bool isConnect = false)
{
	http_parser_url u;
	http_parser_url_init(&u);
	int err = http_parser_parse_url(
			input.c_str(), input.size(), int(isConnect), &u);
	if (err) {
		throw UrlParseError("Failed to parse this url: '" + input + "'");
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
	for (const FieldDef& field: stringFields) {
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

} /* namespace http */

template<typename StreamT>
StreamT& operator<<(StreamT& stream, const http::HttpVersion& ver)
{
	stream << ver.toString();
	return stream;
}

template<typename StreamT>
StreamT& operator<<(StreamT& stream, http::Request::Type reqType)
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
	for (const auto& fvPair: req.headers) {
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
	for (const auto& fvPair: resp.headers) {
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
