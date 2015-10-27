// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//



#include "urlfetch_stream_wrapper.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

#include "php_constants.h"

#include "gae_runtime_module_stub.h"
#include "php_rpc_utils_stub.h"
#include "php_runtime_utils_stub.h"
#include "urlfetch_service.pb.h"

extern "C" {
#ifdef __google_internal__
#include "php/ext/standard/basic_functions.h"
#include "php/ext/standard/php_smart_str.h"
#include "php/ext/standard/php_standard.h"
#include "php/main/php.h"
#include "php/main/php_globals.h"
#include "php/main/php_ini.h"
#include "php/main/php_network.h"
#include "php/main/php_streams.h"
#include "php/main/SAPI.h"
#else
#include "ext/standard/basic_functions.h"
#include "ext/standard/php_smart_str.h"
#include "ext/standard/php_standard.h"
#include "main/php.h"
#include "main/php_globals.h"
#include "main/php_ini.h"
#include "main/php_network.h"
#include "main/php_streams.h"
#include "main/SAPI.h"
#endif
}

using appengine::kErrorCodeName;
using appengine::kMakeApiCallName;
using appengine::kResultStringName;
using appengine::PhpApiRpc;
using apphosting::URLFetchRequest;
using apphosting::URLFetchRequest_Header;
using apphosting::URLFetchResponse;
using apphosting::URLFetchResponse_Header;
using apphosting::URLFetchServiceError;

namespace appengine {

// SSL context options that URL Fetch does not use.
static const char* kSSLContextOptions[] = {
    "allow_self_signed",
    "cafile",
    "capath",
    "local_cert",
    "passphrase",
    "CN_match",
    "verify_depth",
    "ciphers",
    "capture_peer_cert",
    "capture_peer_cert_chain",
    "SNI_enabled",
    "SNI_server_name",
    NULL};

struct php_urlfetch_data {
  URLFetchResponse response;
  size_t buffer_size;
  off_t buffer_read_position;
};

// Reads at most a specified amount of data from the response buffer into the
// read buffer and returns the amount read.
//
// Arguments:
// - stream: The stream from which the request was initated.
// - buf: Reference to the read buffer to copy data to.
// - count: The maximal amount to copy to the read buffer.
//
// Returns: The amount of data that was copied to the read buffer.
static size_t php_urlfetch_read(php_stream* stream,
    char* buf, size_t count TSRMLS_DC) {
  CHECK(stream);
  CHECK(stream->abstract);

  php_urlfetch_data* response_data =
      reinterpret_cast<php_urlfetch_data*>(stream->abstract);

  const char* current_pos = response_data->response.content().c_str();
  off_t read_offset = response_data->buffer_read_position;
  int remaining_in_response_buf = response_data->buffer_size - read_offset;

  if (count > remaining_in_response_buf) {
    count = remaining_in_response_buf;
    stream->eof = 1;
  } else {
    stream->eof = 0;
  }

  memcpy(buf, current_pos + read_offset, count);

  response_data->buffer_read_position += count;
  return count;
}

// Closes the supplied stream. Deconstructs and frees the response buffer and
// associated values.
//
// Arguments:
// - stream: The stream from which the request was initated.
// - close_handle: The close handle.
//
// Returns: 0 if successful.
static int php_urlfetch_close(php_stream* stream, int close_handle TSRMLS_DC) {
  CHECK(stream);
  CHECK(stream->abstract);
  php_urlfetch_data* response_data =
      reinterpret_cast<php_urlfetch_data*>(stream->abstract);
  response_data->~php_urlfetch_data();
  efree(response_data);
  return 0;
}

// Given an URL Fetch HTTP Stream, offset and offset type (whence), move the
// position holder in the response (background) buffer as well as setting
// newoffset to update the read buffer.
//
// Arguments:
// - stream: The stream from which the request was initiated.
// - offset: How much to offset from the current position/start/end.
// - whence: Whether to offset from the current position/start/end.
// - newoffset: Reference to the offset to set in the read buffer.
//
// Returns: 0 if successfully changed position, -1 otherwise.
static int php_urlfetch_seek(php_stream* stream,
                             off_t offset,
                             int whence, off_t* newoffset TSRMLS_DC) {
  CHECK(stream);
  CHECK(stream->abstract);

  php_urlfetch_data* response_data =
      reinterpret_cast<php_urlfetch_data*>(stream->abstract);

  size_t eof_position = response_data->buffer_size;
  off_t new_position;

  switch (whence) {
    case SEEK_CUR:
      // streams.c, _php_stream_seek translates SEEK_CUR to SEEK_SET.
      // We won't encounter SEEK_CUR here, so return -1.
      VLOG(2) << "Unexpected call to seek with SEEK_CUR, ignoring seek.";
      return -1;
      break;
    case SEEK_SET:
      new_position = offset;
      break;
    case SEEK_END:
      new_position = eof_position + offset;
      break;
  }

  if (new_position < 0 || new_position > eof_position) {
    return -1;
  }

  response_data->buffer_read_position = new_position;
  CHECK(newoffset);
  *newoffset = new_position;

  if (new_position + stream->chunk_size < eof_position) {
    stream->eof = 0;
  } else {
    stream->eof = 1;
  }

  return 0;
}

// Returns the message string associated with a http response status code.
// TODO(user): Put this function somewhere common.
//
// Arguments:
// - status_code: The status code to return a message for.
// - status_code_message: Pointer to the string to print the message to.
//
// Returns: True if the message was successfully set.
static bool urlfetch_http_status_message(int status_code,
                                         string* status_code_message) {
  switch (status_code) {
    case 100:
      *status_code_message = "Continue";
      break;
    case 101:
      *status_code_message = "Switching Protocols";
      break;
    case 200:
      *status_code_message = "OK";
      break;
    case 201:
      *status_code_message = "Created";
      break;
    case 202:
      *status_code_message = "Accepted";
      break;
    case 203:
      *status_code_message = "Non-Authoritative Information";
      break;
    case 204:
      *status_code_message = "No Content";
      break;
    case 205:
      *status_code_message = "Reset Content";
      break;
    case 206:
      *status_code_message = "Partial Content";
      break;
    case 300:
      *status_code_message = "Multiple Choices";
      break;
    case 301:
      *status_code_message = "Moved Permanently";
      break;
    case 302:
      *status_code_message = "Moved Temporarily";
      break;
    case 303:
      *status_code_message = "See Other";
      break;
    case 304:
      *status_code_message = "Not Modified";
      break;
    case 305:
      *status_code_message = "Use Proxy";
      break;
    case 400:
      *status_code_message = "Bad Request";
      break;
    case 401:
      *status_code_message = "Unauthorized";
      break;
    case 402:
      *status_code_message = "Payment Required";
      break;
    case 403:
      *status_code_message = "Forbidden";
      break;
    case 404:
      *status_code_message = "Not Found";
      break;
    case 405:
      *status_code_message = "Method Not Allowed";
      break;
    case 406:
      *status_code_message = "Not Acceptable";
      break;
    case 407:
      *status_code_message = "Proxy Authentication Required";
      break;
    case 408:
      *status_code_message = "Request Time-out";
      break;
    case 409:
      *status_code_message = "Conflict";
      break;
    case 410:
      *status_code_message = "Gone";
      break;
    case 411:
      *status_code_message = "Length Required";
      break;
    case 412:
      *status_code_message = "Precondition Failed";
      break;
    case 413:
      *status_code_message = "Request Entity Too Large";
      break;
    case 414:
      *status_code_message = "Request-URI Too Large";
      break;
    case 415:
      *status_code_message = "Unsupported Media Type";
      break;
    case 428:
      *status_code_message = "Precondition Required";
      break;
    case 429:
      *status_code_message = "Too Many Requests";
      break;
    case 431:
      *status_code_message = "Request Header Fields Too Large";
      break;
    case 500:
      *status_code_message = "Internal Server Error";
      break;
    case 501:
      *status_code_message = "Not Implemented";
      break;
    case 502:
      *status_code_message = "Bad Gateway";
      break;
    case 503:
      *status_code_message = "Service Unavailable";
      break;
    case 504:
      *status_code_message = "Gateway Time-out";
      break;
    case 505:
      *status_code_message = "HTTP Version not supported";
      break;
    case 511:
      *status_code_message = "Network Authentication Required";
      break;
    default:
      VLOG(2) << "URL Fetch: Status not found. Code: " << status_code;
      return false;
      break;
  }
  return true;
}

// Takes an application error code and returns the associated error message.
//
// Arguments:
// - error_code: The error code to return a message for.
//
// Returns: The message associated with the error code.
static string urlfetch_application_error_message(const PhpApiRpc& rpc) {
  string message;
  switch (rpc.app_error()) {
    case URLFetchServiceError::INVALID_URL:
      message = "Invalid URL";
      break;
    case URLFetchServiceError::FETCH_ERROR:
      message = "Fetch error";
      break;
    case URLFetchServiceError::RESPONSE_TOO_LARGE:
      message = "Response too large";
      break;
    case URLFetchServiceError::DEADLINE_EXCEEDED:
      message = "Request deadline exceeded";
      break;
    case URLFetchServiceError::SSL_CERTIFICATE_ERROR:
      message = "SSL certificate error - certificate invalid or non-existent";
      break;
    case URLFetchServiceError::DNS_ERROR:
      message = "DNS error";
      break;
    case URLFetchServiceError::CLOSED:
      message = "Connection closed";
      break;
    case URLFetchServiceError::INTERNAL_TRANSIENT_ERROR:
      message = "Internal transient error";
      break;
    case URLFetchServiceError::TOO_MANY_REDIRECTS:
      message = "Too many redirects";
      break;
    case URLFetchServiceError::MALFORMED_REPLY:
      message = "Malformed reply";
      break;
    case URLFetchServiceError::CONNECTION_ERROR:
      message = "Connection error";
      break;
    default:
      // Also catch-all for URLFetchServiceError::UNSPECIFIED_ERROR.
      message = StrCat("Unknown error - ", rpc.app_error());
      break;
  }

  if (!rpc.error_detail().empty()) {
    message = StrCat(message, ", ", rpc.error_detail());
  }
  return message;
}

// Takes a header row string (i.e. header_key: value) and inserts a new header
// item into the supplied request object.
//
// Arguments:
// - header_line: The header row to process.
// - request: The request object to insert the header key/value pair into.
//
// Returns: True if the header pair processed was a user-agent header, false
// otherwise.
static bool urlfetch_header_row_process(const string& header_line,
                                        URLFetchRequest* request TSRMLS_DC) {
  bool header_user_agent = false;
  size_t pos = header_line.find_first_of(":");

  if (pos != string::npos) {
    string header_key = header_line.substr(0, pos);
    string header_value = header_line.substr(pos+1, string::npos);

    TrimWhitespaceASCII(header_key, &header_key);
    TrimWhitespaceASCII(header_value, &header_value);

    if (header_key.empty()) {
      php_error_docref(NULL TSRMLS_CC, E_WARNING,
          "HTTP stream input header contains ill-formatted header rows: %s",
          header_line.c_str());
    } else {
      URLFetchRequest_Header* header = request->add_header();
      header->set_key(header_key);
      header->set_value(header_value);
    }

    if (!header_user_agent &&
        StringCaseEqual(header_key, "user-agent")) {
      header_user_agent = true;
    }
  } else {
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
          "HTTP stream input header contains ill-formatted header rows: %s",
          header_line.c_str());
  }

  return header_user_agent;
}

// Processes a number of header rows supplied in a single string, adding each
// header key/value pair to the supplied request object.
//
// Arguments:
// - header: The string of header rows to process.
// - request: The request object to insert header key/value pairs into.
//
// Returns: True if the header pair processed was a user-agent header, false
// otherwise.
static bool urlfetch_header_process(const string& header,
                                    URLFetchRequest* request TSRMLS_DC) {
  bool header_user_agent = false;
  vector<string> headers;
  SplitString(header, "\n", &headers);

  for (int i = 0; i < headers.size(); ++i) {
    const string& header_line = headers.at(i);
    if (!header_line.empty()) {
      if (urlfetch_header_row_process(header_line, request TSRMLS_CC)) {
        header_user_agent = true;
      }
    }
  }
  return header_user_agent;
}

// Returns the request method associated with that string, or GET if no request
// method can be determined (gives a warning).
//
// Arguments:
// - method_string: A string representation of the method choice.
// - wrapper: Contains the wrapper data for error logging.
// - options: Contains wrapper opener options for error logging.
//
// Returns: The URLFetchRequest::RequestMethod associated with that string.
static URLFetchRequest::RequestMethod urlfetch_method(string method_string,
    php_stream_wrapper* wrapper, int options TSRMLS_DC) {
  if (StringCaseEqual(method_string, "GET")) {
    return URLFetchRequest::GET;
  } else if (StringCaseEqual(method_string, "POST")) {
    return URLFetchRequest::POST;
  } else if (StringCaseEqual(method_string, "HEAD")) {
    return URLFetchRequest::HEAD;
  } else if (StringCaseEqual(method_string, "PUT")) {
    return URLFetchRequest::PUT;
  } else if (StringCaseEqual(method_string, "DELETE")) {
    return URLFetchRequest::DELETE;
  } else if (StringCaseEqual(method_string, "PATCH")) {
    return URLFetchRequest::PATCH;
  }
  php_error_docref(NULL TSRMLS_CC, E_WARNING,
      "Invalid method: %s. Must be of GET, POST, HEAD, PUT, DELETE or PATCH. "
      "Defaulting to GET.",
      method_string.c_str());
  return URLFetchRequest::GET;
}

// Populates the $http_response_header array with the response headers from URL
// Fetch.
//
// Arguments:
// - response_data: Contains the response protobuf.
// - wrapper: Contains the wrapper data for error logging.
// - options: Contains wrapper opener options for error logging.
//
// Returns: A pointer to the response header ZEND array.
static zval* urlfetch_populate_response_header(
    php_urlfetch_data* response_data, php_stream_wrapper* wrapper,
    int options TSRMLS_DC) {
  if (!EG(active_symbol_table)) {
    zend_rebuild_symbol_table(TSRMLS_C);
  }
  zval* ztmp;
  MAKE_STD_ZVAL(ztmp);
  array_init(ztmp);
  ZEND_SET_SYMBOL(EG(active_symbol_table),
      const_cast<char *>("http_response_header"), ztmp);

  zval** rh;
  zend_hash_find(EG(active_symbol_table),
                 const_cast<char*>("http_response_header"),
                 sizeof("http_response_header"),
                 reinterpret_cast<void**>(&rh));
  CHECK(rh);
  zval* response_header = *rh;

  int status_code = response_data->response.statuscode();

  string status_code_message = "";
  if (!urlfetch_http_status_message(status_code, &status_code_message)) {
    php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown status code.");
  }

  // We use a HTTP/1.1 compliant proxy.
  string response_row_buf = StringPrintf("HTTP/1.1 %d %s",
                                         status_code,
                                         status_code_message.c_str());

  zval* http_response_default;
  MAKE_STD_ZVAL(http_response_default);
  ZVAL_STRINGL(http_response_default,
      response_row_buf.c_str(), response_row_buf.length(), 1);
  zend_hash_next_index_insert(Z_ARRVAL_P(response_header),
      &http_response_default, sizeof(zval*), NULL);

  // Insert the remaining headers.
  int num_header_rows = response_data->response.header_size();
  string protocol_and_version = "";
  for (int i = 0; i < num_header_rows; ++i) {
    const URLFetchResponse_Header& header_row =
        response_data->response.header(i);

    string tmp_line = StrCat(header_row.key(), ": ", header_row.value());
    zval* http_response;
    MAKE_STD_ZVAL(http_response);
    ZVAL_STRINGL(http_response, tmp_line.c_str(), tmp_line.length(), 1);
    zend_hash_next_index_insert(Z_ARRVAL_P(response_header), &http_response,
        sizeof(zval*), NULL);
  }

  return response_header;
}

static php_stream_ops http_stream_ops = {
  NULL,  // write
  php_urlfetch_read,  // read
  php_urlfetch_close,  // close
  NULL,  // flush
  "http via urlfetch",  // label
  php_urlfetch_seek,  // seek
  NULL,  // cast
  NULL,  // stat
  NULL  // set_option
};

// Called to open a new URL Fetch HTTP/HTTPS stream. Parses inputs, forms a URL
// Fetch protobuf, makes the request, parse outputs, buffers the response data
// and stores stream meta data as appropriate.
//
// Arguments:
// - wrapper: The appropriate wrapper to use to process the data and make the
// request. Used for ensuring errors and correctly logged.
// - path: The URL for the request. Of the form http://host or https://host.
// - mode: The mode with which to open the request. Either read- 'r' or read
// binary- 'rb'. Write modes are invalid for HTTP streams.
// - options: Flag concerning STREAM_USE_PATH and STREAM_REPORT_ERRORS.
// - opened_path: The actual path that was opened.
// - context: Context options to consider when making the request.
//
// Returns: A stream object containing the relevant data to perform stream
// operations.
static php_stream* urlfetch_stream_wrapper(php_stream_wrapper* wrapper,
    char* path,
    char* mode,
    int options,
    char** opened_path,
    php_stream_context* context STREAMS_DC TSRMLS_DC) {

  CHECK(wrapper);
  CHECK(path);
  CHECK(mode);

  zval** tmpzval = NULL;

  const string url = path;
  const string separator = "://";

  size_t pos = url.find(separator);
  if (pos == string::npos) {
    php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
        "URL %s is not correctly formatted. Use http://hostname or "
        "https://hostname.", url.c_str());
    return NULL;
  }
  const string url_scheme = url.substr(0, pos);
  const string full_url_without_scheme = url.substr(pos + separator.length());

  if (!StringCaseEqual(url_scheme, "http") &&
      !StringCaseEqual(url_scheme, "https")) {
    php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
        "Invalid wrapper scheme for this wrapper. Use http:// or https://.");
    return NULL;
  } else if (full_url_without_scheme.empty()) {
    php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
        "The URL %s is invalid. Use http://hostname or "
        "https://hostname.", url.c_str());
    return NULL;
  }

  string open_mode = mode;
  if (open_mode.find_first_of("awx+") != string::npos) {
    php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
        "HTTP streams do not support writeable connections.");
    return NULL;
  }

  URLFetchRequest request;

  // Extract the authority from the url, so we can check for basic auth.
  string authority = full_url_without_scheme;
  pos = authority.find('/');
  if (pos != string::npos) {
    authority = authority.substr(0, pos);
  }

  // Support for basic auth in the authority, in user:pass format
  // https://tools.ietf.org/html/rfc3986#section-3.2.1
  const string at_sign = "@";
  pos = authority.find_first_of(at_sign);
  if (pos != string::npos) {
    string userinfo = full_url_without_scheme.substr(0, pos);
    // Update the URL to remove the user:pass
    string updated_path = StrCat(url_scheme,
                                 separator,
                                 full_url_without_scheme.substr(
                                     pos + at_sign.length()));
    request.set_url(updated_path);

    // Add a header for the Basic Authorization
    string base64_encoded;
    EncodeBase64(userinfo, &base64_encoded);
    URLFetchRequest_Header* header = request.add_header();
    header->set_key("Authorization");
    header->set_value(StrCat("Basic ", base64_encoded));
  } else {
    request.set_url(path);
  }

  if (context && php_stream_context_get_option(
      context, "http", "timeout", &tmpzval) == SUCCESS) {
    SEPARATE_ZVAL(tmpzval);
    convert_to_double_ex(tmpzval);
    request.set_deadline(Z_DVAL_PP(tmpzval));
  } else {
    double default_socket_timeout =
        static_cast<double>(FG(default_socket_timeout));
    if (default_socket_timeout > 0) {
      request.set_deadline(static_cast<double>(FG(default_socket_timeout)));
    }
  }

  int redirect_max = 5;
  if (context && php_stream_context_get_option(
      context, "http", "max_redirects", &tmpzval) == SUCCESS) {
    SEPARATE_ZVAL(tmpzval);
    convert_to_long_ex(tmpzval);
    redirect_max = static_cast<int>(Z_LVAL_PP(tmpzval));
  }

  int follow_location = 1;
  if (context && php_stream_context_get_option(
      context, "http", "follow_location", &tmpzval) == SUCCESS) {
    SEPARATE_ZVAL(tmpzval);
    convert_to_long_ex(tmpzval);
    follow_location = Z_LVAL_PP(tmpzval);
  }

  bool follow_redirects = true;
  if (redirect_max <= 1 || follow_location == 0) {
    follow_redirects = false;
  }
  request.set_followredirects(follow_redirects);

  if (context && php_stream_context_get_option(
      context, "http", "method", &tmpzval) == SUCCESS) {
    if (Z_TYPE_PP(tmpzval) == IS_STRING && Z_STRLEN_PP(tmpzval) > 0) {
      string method_string = Z_STRVAL_PP(tmpzval);
      URLFetchRequest::RequestMethod method = urlfetch_method(method_string,
          wrapper, options TSRMLS_CC);
      request.set_method(method);
    } else {
      php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
          "Invalid method. Must be a string.");
      return NULL;
    }
  } else {
    // The default context is GET if another context is not set.
    request.set_method(URLFetchRequest::GET);
  }

  // Precendence of user-agent: header, context option, ini file.
  bool header_user_agent = false;
  if (context && php_stream_context_get_option(
      context, "http", "header", &tmpzval) == SUCCESS) {
    char* tmp = NULL;
    if (Z_TYPE_PP(tmpzval) == IS_STRING && Z_STRLEN_PP(tmpzval)) {
      tmp = Z_STRVAL_PP(tmpzval);
    } else {
      php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
          "Invalid headers. Must be a string.");
      return NULL;
    }

    if (tmp && strlen(tmp) > 0) {
      string header = tmp;
      if (header.find("\n") == string::npos) {
        header_user_agent = urlfetch_header_row_process(header,
                                                        &request TSRMLS_CC);
      } else {
        header_user_agent = urlfetch_header_process(header,
                                                    &request TSRMLS_CC);
      }
    }
  }

  // Precendence of remaining options: user-agent context option, ini file.
  if (!header_user_agent) {
    if (context && php_stream_context_get_option(
        context, "http", "user-agent", &tmpzval) == SUCCESS) {
      if (Z_TYPE_PP(tmpzval) == IS_STRING && Z_STRLEN_PP(tmpzval)) {
        char* tmp = Z_STRVAL_PP(tmpzval);
        apphosting::URLFetchRequest_Header* header = request.add_header();
        header->set_key("user-agent");
        header->set_value(tmp);
      } else {
        php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
            "Invalid user-agent field. Must be a string");
        return NULL;
      }
    } else {
      const char* user_agent = FG(user_agent);
      if (user_agent && *user_agent) {
        apphosting::URLFetchRequest_Header* header = request.add_header();
        header->set_key("user-agent");
        header->set_value(user_agent);
      }
    }
  }

  URLFetchRequest::RequestMethod request_method =
      (URLFetchRequest::RequestMethod) request.method();
  if (request_method == URLFetchRequest::POST ||
      request_method == URLFetchRequest::PUT ||
      request_method == URLFetchRequest::PATCH) {
    if (context && php_stream_context_get_option(
        context, "http", "content", &tmpzval) == SUCCESS) {
      if (Z_TYPE_PP(tmpzval) == IS_STRING && Z_STRLEN_PP(tmpzval)) {
        string payload(Z_STRVAL_PP(tmpzval), Z_STRLEN_PP(tmpzval));
        request.set_payload(payload);
      }
    }
  }

  bool must_validate_server_certificate = true;
  if (url_scheme.compare("http") == 0) {
    must_validate_server_certificate = false;
  }
  if (context && php_stream_context_get_option(
      context, "ssl", "verify_peer", &tmpzval) == SUCCESS) {
    must_validate_server_certificate = Z_LVAL_PP(tmpzval);
  }
  request.set_mustvalidateservercertificate(must_validate_server_certificate);

  if (context && (url_scheme.compare("https") == 0)) {
    // Check for SSL context options that we don't support, print debug message.
    string ssl_context_errors;
    for (int i = 0; kSSLContextOptions[i] != NULL; ++i) {
      if (php_stream_context_get_option(
        context, "ssl", kSSLContextOptions[i], &tmpzval) == SUCCESS) {
        ssl_context_errors = StrCat(ssl_context_errors,
                                    ssl_context_errors.empty() ? "" : ", ",
                                    kSSLContextOptions[i]);
      }
    }

    if (!ssl_context_errors.empty()) {
      // Using php_stream_wrapper_log_error here leads to confusing error
      // messages for users if there is an error making the RPC call. Just
      // log this message directly instead.
      string message = StringPrintf(
          "Unsupported SSL context options are set. The following options are "
          "present, but have been ignored: %s", ssl_context_errors.c_str());
      sapi_module.log_message(const_cast<char*>(message.c_str()) TSRMLS_CC);
    }
  }

  PhpApiRpc rpc;
  string request_string;
  string response_string;
  request.SerializeToString(&request_string);

  PhpRpcUtils::MakeApiCall(&rpc, "urlfetch", "Fetch", request_string,
      request.deadline() TSRMLS_CC);

  if (rpc.error() != PhpApiRpc::OK) {
    switch (rpc.error()) {
      case PhpApiRpc::RPC_FAILED:
        php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
            "RPC Error: Call failed.");
        break;
      case PhpApiRpc::CALL_NOT_FOUND:
        php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
            "RPC Error: Call not found.");
        break;
      case PhpApiRpc::APPLICATION_ERROR:
        php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
            "%s", urlfetch_application_error_message(rpc).c_str());
        break;
      default:
        php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
            "RPC Error: Unknown error - %d.", rpc.error());
        break;
    }
    return NULL;
  }

  void* place = ecalloc(1, sizeof(php_urlfetch_data));
  php_urlfetch_data* response_data = new(place) php_urlfetch_data();
  response_data->response.ParseFromString(rpc.response_pb());

  zval* response_header = urlfetch_populate_response_header(
      response_data, wrapper, options TSRMLS_CC);

  response_data->buffer_read_position = 0;
  response_data->buffer_size = response_data->response.content().length();

  php_stream* stream =
      php_stream_alloc(&http_stream_ops, response_data, 0, mode);

  if (response_data->buffer_size > 0) {
    stream->eof = 0;
  } else {
    // If the response has no content.
    stream->eof = 1;
  }

  MAKE_STD_ZVAL(stream->wrapperdata);
  MAKE_COPY_ZVAL(&response_header, stream->wrapperdata);

  return stream;
}

static php_stream_wrapper_ops urlfetch_stdio_wops = {
  urlfetch_stream_wrapper,  // open/create
  NULL,  // close
  NULL,  // stream_stat
  NULL,  // url_stat
  NULL,  // dir_opener
  "http via urlfetch",  // label
  NULL,  // unlink
  NULL,  // rename
  NULL,  // stream_mkdir
  NULL  // stream_rmdir
};

php_stream_wrapper urlfetch_stream_http_wrapper = {
  &urlfetch_stdio_wops,  // operations a wrapper can perform
  NULL,  // context for the wrapper
  1  // is_url, so that allow_url_fopen can be checked.
};

static const zend_function_entry urlfetch_stream_wrapper_functions[] = {
  PHP_FE_END
};

static const zend_module_dep urlfetch_stream_wrapper_dep[] = {
  ZEND_MOD_END
};

static PHP_MINIT_FUNCTION(urlfetch_stream_wrapper) {
  // Remove whatever might already be there
  php_unregister_url_stream_wrapper(const_cast<char *>("http") TSRMLS_CC);
  php_unregister_url_stream_wrapper(const_cast<char *>("https") TSRMLS_CC);

  // Register our URL fetch stream wrapper
  php_register_url_stream_wrapper(const_cast<char *>("http"),
                                  &urlfetch_stream_http_wrapper TSRMLS_CC);
  php_register_url_stream_wrapper(const_cast<char *>("https"),
                                  &urlfetch_stream_http_wrapper TSRMLS_CC);

  return SUCCESS;
}

static PHP_MSHUTDOWN_FUNCTION(urlfetch_stream_wrapper) {
  php_unregister_url_stream_wrapper(const_cast<char *>("http") TSRMLS_CC);
  php_unregister_url_stream_wrapper(const_cast<char *>("https") TSRMLS_CC);
  return SUCCESS;
}

static PHP_RINIT_FUNCTION(urlfetch_stream_wrapper) {
  return SUCCESS;
}

static PHP_RSHUTDOWN_FUNCTION(urlfetch_stream_wrapper) {
  return SUCCESS;
}

zend_module_entry urlfetch_stream_wrapper_module_entry = {
  STANDARD_MODULE_HEADER_EX,
  NULL,
  urlfetch_stream_wrapper_dep,
  "urlfetch_stream_wrapper_plugin",
  urlfetch_stream_wrapper_functions,
  PHP_MINIT(urlfetch_stream_wrapper),
  PHP_MSHUTDOWN(urlfetch_stream_wrapper),
  PHP_RINIT(urlfetch_stream_wrapper),
  PHP_RSHUTDOWN(urlfetch_stream_wrapper),
  NULL,
  NO_VERSION_YET,
  STANDARD_MODULE_PROPERTIES
};

}  // namespace appengine
