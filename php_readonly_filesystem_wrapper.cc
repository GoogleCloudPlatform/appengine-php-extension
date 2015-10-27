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

// Author: slangley@google.com (Stuart Langley)
#include "php_readonly_filesystem_wrapper.h"

namespace appengine {

// Keep a track of the original operations, in case we need them. Right now we
// only re-use stream_opener
static php_stream_wrapper_ops original_ops;

static void show_php_error(const char* function_name TSRMLS_DC) {
  // E_WARNING as we don't want to terminate script execution.
  php_error_docref(NULL TSRMLS_CC,
                   E_WARNING,
                   "The local filesystem is readonly, %s failed",
                   function_name);
}

static int disabled_rename(php_stream_wrapper* wrapper,
                           char* url_from,
                           char* url_to,
                           int options,
                           php_stream_context *context TSRMLS_DC) {
  // Rename never sets options to a non zero value, so we will always print this
  // warning.
  show_php_error("rename" TSRMLS_CC);
  errno = EROFS;
  return 0;
}

static int disabled_unlink(php_stream_wrapper* wrapper,
                           char* url,
                           int options,
                           php_stream_context* context TSRMLS_DC) {
  if (options & REPORT_ERRORS) {
    show_php_error("unlink" TSRMLS_CC);
  }
  errno = EROFS;
  return 0;
}

static int disabled_mkdir(php_stream_wrapper* wrapper,
                          char* url,
                          int mode,
                          int options,
                          php_stream_context* context TSRMLS_DC) {
  if (options & REPORT_ERRORS) {
    show_php_error("mkdir" TSRMLS_CC);
  }
  errno = EROFS;
  return 0;
}

static php_stream* disabled_write_stream_opener(php_stream_wrapper* wrapper,
    char* path, char* mode, int options, char** opened_path,
    php_stream_context* context STREAMS_DC TSRMLS_DC) {

  if (mode[0] != 'r' || strchr(mode, '+') != NULL) {
    php_error_docref1(NULL TSRMLS_CC,
                      path,
                      E_WARNING,
                      "The local filesystem is readonly, open failed");
    errno = EROFS;
    return NULL;
  }

  // Defer to the original implementation.
  return original_ops.stream_opener(wrapper,
                                    path,
                                    mode,
                                    options,
                                    opened_path,
                                    context STREAMS_CC TSRMLS_CC);
}

static int disabled_rmdir(php_stream_wrapper* wrapper,
                          char* url,
                          int options,
                          php_stream_context* context TSRMLS_DC) {
  if (options & REPORT_ERRORS) {
    show_php_error("rmdir" TSRMLS_CC);
  }
  errno = EROFS;
  return 0;
}

void hook_readonly_filesystem_wrapper(php_stream_wrapper* wrapper TSRMLS_DC) {
  php_stream_wrapper_ops* ops = wrapper->wops;
  // Only if we have not already hooked this.
  if (ops->stream_opener != disabled_write_stream_opener) {
    // Keep a copy of what was once there.
    ::memcpy(&original_ops, ops, sizeof(original_ops));

    // Replace the functions we are flat out disabling.
    ops->stream_opener = disabled_write_stream_opener;
    ops->unlink = disabled_unlink;
    ops->rename = disabled_rename;
    ops->stream_mkdir = disabled_mkdir;
    ops->stream_rmdir = disabled_rmdir;
  }
}

}  // namespace appengine
