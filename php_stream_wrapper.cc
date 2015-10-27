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

// Author: slangley@google.com (Stuart Langley)

// This is a substitute stream wrapper for the standard php:// stream wrapper,
// which has been removed in GAE due to the potential for security exploits in
// the standard stream.
//
// We will be adding a limited number of php:// streams that are deemed useful
// and not a potential security risk.
//
// Streams currently supported.
// * php://input - For reading POST data sent to the app.
// * php://output - For writing to the response that will be sent.
// * php://memory - For working with memory based streams.
// * php://temp - For working with temporary data (uses memory).

#include "php_stream_wrapper.h"

#include "gae_runtime_module_stub.h"

extern "C" {
#ifdef __google_internal__
#include "php/main/SAPI.h"
#else
#include "main/SAPI.h"
#endif
}

DECLARE_bool(php_enable_php_output_stream);

namespace appengine {

static const char kProtocolSeparator[] = "://";
static const int kProtocolSeparatorLength = sizeof(kProtocolSeparator) - 1;
static const char kProtocol[] = "php";
static const char kPostDataPathName[] = "input";
static const char kInvalidOpenModes[] = "awx+";
static const char kOutputDataPathName[] = "output";

// State that is associated with the stream.
struct input_stream_data {
  input_stream_data()
      : read_position(0) {}

  void* operator new(size_t bytes) {
    return emalloc(bytes);
  }

  void operator delete(void* ptr) {
    efree(ptr);
  }

  void* operator new[](size_t bytes);
  void operator delete[](void* ptr);

  off_t read_position;
};

static size_t php_stream_input_write(php_stream* stream,
                                     const char* buffer,
                                     size_t count TSRMLS_DC) {
  return -1;
}

static size_t php_stream_input_read(php_stream* stream,
                                    char* buffer,
                                    size_t count TSRMLS_DC) {
  CHECK(stream);
  CHECK(stream->abstract);
  CHECK(buffer);

  input_stream_data* data =
      reinterpret_cast<input_stream_data*>(stream->abstract);
  size_t read_bytes = 0;

  if (!stream->eof) {
    // If always-populate-raw-post-data is on then we can memcpy from the
    // in memory copy of the POST data.
    if (SG(request_info).raw_post_data) {
      read_bytes = SG(request_info).raw_post_data_length - data->read_position;
      if (read_bytes <= count) {
        stream->eof = 1;
      } else {
        read_bytes = count;
      }
      if (read_bytes) {
        memcpy(buffer,
               SG(request_info).raw_post_data + data->read_position,
               read_bytes);
      }
    } else if (sapi_module.read_post) {
      // When reading from the sapi module, the sapi keeps track of the current
      // position in the stream.
      read_bytes = sapi_module.read_post(buffer, count TSRMLS_CC);
      if (read_bytes <= 0) {
        stream->eof = 1;
        read_bytes = 0;
      }
      SG(read_post_bytes) += read_bytes;
    } else {
      stream->eof = 1;
    }
  }

  data->read_position += read_bytes;
  return read_bytes;
}

static int php_stream_input_close(php_stream *stream,
                                  int close_handle TSRMLS_DC) {
  CHECK(stream);
  CHECK(stream->abstract);

  input_stream_data* data =
      reinterpret_cast<input_stream_data*>(stream->abstract);
  delete data;
  return 0;
}

static int php_stream_input_flush(php_stream *stream TSRMLS_DC) {
  return -1;
}

static php_stream_ops php_stream_input_ops = {
  php_stream_input_write,
  php_stream_input_read,
  php_stream_input_close,
  php_stream_input_flush,
  "Input",
  NULL,  // seek
  NULL,  // cast
  NULL,  // stat
  NULL   // set_option
};

static size_t php_stream_output_write(php_stream* stream,
                                      const char* buf,
                                      size_t count TSRMLS_DC) {
  php_output_write(buf, count TSRMLS_CC);
  return count;
}

static size_t php_stream_output_read(php_stream* stream,
                                     char* buf,
                                     size_t count TSRMLS_DC) {
  stream->eof = 1;
  return 0;
}

static int php_stream_output_close(php_stream* stream,
                                   int close_handle TSRMLS_DC) {
  return 0;
}

static php_stream_ops php_stream_output_ops = {
  php_stream_output_write,
  php_stream_output_read,
  php_stream_output_close,
  NULL,  // flush
  "Output",
  NULL,  // seek
  NULL,  // cast
  NULL,  // stat
  NULL   // set_option
};

static php_stream* input_stream_wrapper(php_stream_wrapper* wrapper,
                                        char* path,
                                        char* mode,
                                        int options,
                                        char** opened_path,
                                        php_stream_context* context
                                        STREAMS_DC TSRMLS_DC) {
  CHECK(wrapper);
  CHECK(path);
  CHECK(mode);

  string mode_str(mode);
  string path_str(path);

  size_t protocol_pos = path_str.find(kProtocolSeparator);
  string protocol;
  string data_path;

  if (protocol_pos != string::npos) {
    protocol = path_str.substr(0, protocol_pos);
    data_path = path_str.substr(protocol_pos + kProtocolSeparatorLength);
  } else {
    data_path = path_str;
  }

  if (!protocol.empty()) {
    if (strcasecmp(protocol.c_str(), kProtocol) != 0) {
      php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
        "Protocol name %s is invalid. Only %s is supported.",
        protocol.c_str(), kProtocol);
    return NULL;
    }
  }

  if (strcasecmp(data_path.c_str(), kPostDataPathName) == 0) {
    if (mode_str.find_first_of(kInvalidOpenModes) != string::npos) {
      php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
          "Invalid open mode %s", mode);
      return NULL;
    }

    input_stream_data* data = new input_stream_data();
    return php_stream_alloc(&php_stream_input_ops, data, 0, mode);
  } else if (FLAGS_php_enable_php_output_stream &&
             strcasecmp(data_path.c_str(), kOutputDataPathName) == 0) {
    // The original PHP does not bother checking the mode of php://output, just
    // sets it as "wb"
    return php_stream_alloc(&php_stream_output_ops, NULL, 0, "wb");
  } else if ((strncasecmp(data_path.c_str(), "temp", 4) == 0) ||
             (strcasecmp(data_path.c_str(), "memory") == 0)) {
    // The "temp" stream can specify an amount of memory past which the
    // implementation should use a temporary file e.g.
    // "php://temp/maxmemory:2097152". The App Engine implementation always
    // uses memory and ignores negative maximums (which are normally an error).
    int mode_rw = 0;
    if (strpbrk(mode, "wa+")) {
      mode_rw = TEMP_STREAM_DEFAULT;
    } else {
      mode_rw = TEMP_STREAM_READONLY;
    }
    return php_stream_memory_create(mode_rw);
  }

  php_stream_wrapper_log_error(wrapper, options TSRMLS_CC,
      "Unknown stream type %s%s%s.",
      kProtocol, kProtocolSeparator, data_path.c_str());

  return NULL;
}

static php_stream_wrapper_ops php_stdio_wops = {
  input_stream_wrapper,
  NULL,  // close
  NULL,  // fstat
  NULL,  // stat
  NULL,  // opendir
  "PHP",
  NULL,  // unlink
  NULL,  // rename
  NULL,  // mkdir
  NULL   // rmdir
};

php_stream_wrapper php_input_stream_wrapper = {
  &php_stdio_wops,
  NULL,
  1,  // is_url
};

}  // namespace appengine
