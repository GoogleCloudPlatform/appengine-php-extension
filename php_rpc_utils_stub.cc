// Copyright 2015 Google Inc. All Rights Reserved.
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

// Author: marslan@google.com (Mars Lan)

#include <string>

#include "php_rpc_utils_stub.h"
#include "php_runtime_utils_stub.h"

#include "remote_api.pb.h"

extern "C" {
#include "main/php.h"
#include "ext/standard/php_fopen_wrappers.h"
}

using apphosting::ext::remote_api::Request;
using apphosting::ext::remote_api::Response;

namespace appengine {

void PhpRpcUtils::MakeApiCall(PhpApiRpc* rpc,
                              const string& package_name,
                              const string& call_name,
                              const string& request_pb,
                              double deadline_sec TSRMLS_DC) {
  const char* api_host = getenv("REMOTE_API_HOST");
  if (!api_host) {
    php_error_docref(NULL TSRMLS_CC, E_ERROR,
        "Missing required REMOTE_API_HOST enviornmental variable.");
    return;
  }

  int api_port = 0;
  const char* api_port_env = getenv("REMOTE_API_PORT");
  if (!api_port_env) {
    php_error_docref(NULL TSRMLS_CC, E_ERROR,
        "Missing required REMOTE_API_PORT enviornmental variable.");
    return;
  } else {
    api_port = static_cast<int>(
        strtol(api_port_env, NULL, 10));  // NOLINT(runtime/deprecated_fn)
  }

  if (api_port <= 0 || api_port > USHRT_MAX) {
    php_error_docref(NULL TSRMLS_CC, E_ERROR,
        "Invalid REMOTE_API_PORT value %s", api_port_env);
  }

  const char* request_id = getenv("REMOTE_REQUEST_ID");
  if (!request_id) {
    php_error_docref(NULL TSRMLS_CC, E_ERROR,
        "Missing required REMOTE_REQUEST_ID enviornmental variable.");
    return;
  }

  php_stream_wrapper* wrapper = &php_stream_http_wrapper;
  php_stream_wrapper_ops* wops = wrapper->wops;

  // Wrap RPC in a Remote API Request proto.
  Request* remote_request = new Request();
  remote_request->set_service_name(package_name);
  remote_request->set_method(call_name);
  remote_request->set_request(request_pb.c_str(), request_pb.length());
  remote_request->set_request_id(request_id);
  string content = remote_request->SerializeAsString();
  int content_len = remote_request->ByteSize();

  // Setup stream context.
  php_stream_context* context = php_stream_context_alloc(TSRMLS_C);

  zval method_val;
  ZVAL_STRING(&method_val, "POST", 0);
  php_stream_context_set_option(context, wops->label, "method", &method_val);

  string header = StringPrintf("Content-type: application/octet-stream\r\n"
                               "Content-length: %d\r\n", content_len);
  zval header_val;
  ZVAL_STRING(&header_val, header.c_str(), 0);
  php_stream_context_set_option(context, wops->label, "header", &header_val);


  zval content_val;
  ZVAL_STRINGL(&content_val, content.c_str(), content_len, 0);
  php_stream_context_set_option(context, wops->label, "content", &content_val);

  string url = StringPrintf("http://%s:%d/", api_host, api_port);
  char* opened_path;
  php_stream* stream = wops->stream_opener(
      wrapper, const_cast<char *>(url.c_str()),
      const_cast<char *>("rb"), REPORT_ERRORS, &opened_path, context
      STREAMS_CC TSRMLS_CC);
  if (!stream) {
    rpc->set_error(PhpApiRpc::RPC_FAILED);
    php_error_docref(NULL TSRMLS_CC, E_ERROR,
                     "Invalid response from API server.");
    php_stream_close(stream);
    return;
  }

  char* buffer;
  int len = php_stream_copy_to_mem(stream, &buffer, PHP_STREAM_COPY_ALL, 0);
  if (len < 0) {
    rpc->set_error(PhpApiRpc::RPC_FAILED);
    php_error_docref(NULL TSRMLS_CC, E_ERROR,
                     "Cannot read API server's response.");
    php_stream_close(stream);
    return;
  }

  Response *remote_response = new Response();
  remote_response->ParseFromArray(buffer, len);
  efree(buffer);

  if (remote_response->has_application_error()) {
    rpc->set_error(PhpApiRpc::APPLICATION_ERROR);
    rpc->set_app_error(remote_response->application_error().code());
    rpc->set_error_detail(remote_response->application_error().detail());
  } else if (remote_response->has_exception() ||
      remote_response->has_java_exception()) {
    rpc->set_error(PhpApiRpc::RPC_FAILED);
    php_error_docref(NULL TSRMLS_CC, E_ERROR,
                     "Remote implementation for %s.%s failed",
                     package_name.c_str(), call_name.c_str());
  } else {
    rpc->set_error(PhpApiRpc::OK);
    rpc->set_response_pb(remote_response->response());
  }

  php_stream_close(stream);
}

}  // namespace appengine
