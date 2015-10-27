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
#include "php_redirect_filesystem_wrapper.h"

#include <string>

#include "gae_runtime_module.h"

namespace appengine {

static php_stream* redirect_stream_opener(php_stream_wrapper* orig_wrapper,
    char* filename, char* mode, int options, char** opened_path,
    php_stream_context* context STREAMS_DC TSRMLS_DC) {

  char* actual_path;
  php_stream_wrapper* wrapper = appengine::get_correct_stream_wrapper(filename,
      &actual_path,  options TSRMLS_CC);
  if (wrapper) {
    return wrapper->wops->stream_opener(wrapper, actual_path, mode, options,
        opened_path, context STREAMS_CC TSRMLS_CC);
  }
  return NULL;
}

static int redirect_url_stat(php_stream_wrapper* orig_wrapper, char* url,
    int flags, php_stream_statbuf* ssb, php_stream_context* context TSRMLS_DC) {
  char* actual_path = NULL;
  // Clear the flag IGNORE_URL when looking up the correct wrapper, specifically
  // for the case when doing a file_exists() check. PHP will set the flag
  // PHP_STREAM_URL_STAT_QUIET which just happens to have the same value as
  // IGNORE_URL which causes php_stream_locate_url_wrapper to return
  // plain_files_wrapper.
  php_stream_wrapper* wrapper = appengine::get_correct_stream_wrapper(url,
      &actual_path, flags & ~IGNORE_URL TSRMLS_CC);
  if (wrapper) {
    return wrapper->wops->url_stat(wrapper, actual_path, flags, ssb,
        context TSRMLS_CC);
  }
  return 0;
}

static php_stream* redirect_dir_opener(php_stream_wrapper* orig_wrapper,
    char* filename, char* mode, int options, char** opened_path,
    php_stream_context* context STREAMS_DC TSRMLS_DC) {
  char* actual_path = NULL;
  php_stream_wrapper* wrapper = appengine::get_correct_stream_wrapper(filename,
      &actual_path, options TSRMLS_CC);
  if (wrapper) {
    return wrapper->wops->dir_opener(wrapper, actual_path, mode, options,
        opened_path, context STREAMS_CC TSRMLS_CC);
  }
  return NULL;
}

static int redirect_unlink(php_stream_wrapper* orig_wrapper, char* url,
    int options, php_stream_context* context TSRMLS_DC) {
  char* new_path;
  if (is_redirect_path(url, &new_path TSRMLS_CC)) {
    char* actual_path;
    php_stream_wrapper* wrapper = appengine::get_correct_stream_wrapper(
        new_path, &actual_path, options TSRMLS_CC);
    if (wrapper) {
      return wrapper->wops->unlink(wrapper, actual_path, options,
          context TSRMLS_CC);
    }
  }
  return 0;
}

static int redirect_stream_mkdir(php_stream_wrapper* orig_wrapper, char* url,
    int mode, int options, php_stream_context* context TSRMLS_DC) {
  char* new_path = NULL;
  if (is_redirect_path(url, &new_path TSRMLS_CC)) {
    char* actual_path = NULL;
    php_stream_wrapper* wrapper = appengine::get_correct_stream_wrapper(
        new_path, &actual_path, options TSRMLS_CC);
    if (wrapper) {
      return wrapper->wops->stream_mkdir(wrapper, actual_path, mode, options,
          context TSRMLS_CC);
    }
  }
  return 0;
}

static int redirect_stream_rmdir(php_stream_wrapper* orig_wrapper, char* url,
    int options, php_stream_context* context TSRMLS_DC) {
  char* new_path = NULL;
  if (is_redirect_path(url, &new_path TSRMLS_CC)) {
    char* actual_path = NULL;
    php_stream_wrapper* wrapper = appengine::get_correct_stream_wrapper(
        new_path, &actual_path, options TSRMLS_CC);
    if (wrapper) {
      return wrapper->wops->stream_rmdir(wrapper, actual_path, options,
          context TSRMLS_CC);
    }
  }
  return 0;
}

static int redirect_stream_metadata(php_stream_wrapper* orig_wrapper, char* url,
    int options, void* value, php_stream_context* context TSRMLS_DC) {
  char* redirect_path;
  if (is_redirect_path(url, &redirect_path TSRMLS_CC)) {
    char* actual_path;
    php_stream_wrapper* wrapper = appengine::get_correct_stream_wrapper(
        redirect_path, &actual_path, options TSRMLS_CC);
    if (wrapper) {
      return wrapper->wops->stream_metadata(wrapper, actual_path, options,
          value, context TSRMLS_CC);
    }
  }
  return 0;
}

static int redirect_stream_rename(php_stream_wrapper* wrapper, char* url_from,
    char* url_to, int options, php_stream_context *context TSRMLS_DC) {
  // Supported in the cross wrapper rename function.
  return 0;
}

static php_stream_wrapper_ops redirect_stdio_wops = {
  redirect_stream_opener,
  NULL,
  NULL,
  redirect_url_stat,
  redirect_dir_opener,
  "redirect",
  redirect_unlink,
  redirect_stream_rename,
  redirect_stream_mkdir,
  redirect_stream_rmdir,
  redirect_stream_metadata,
};

php_stream_wrapper php_redirect_stream_wrapper = {
  &redirect_stdio_wops,
  NULL,
  1,  // is_url
};

}  // namespace appengine
