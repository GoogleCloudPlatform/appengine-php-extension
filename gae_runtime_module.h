// Copyright 2012 Google Inc. All Rights Reserved.
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

#ifndef GAE_RUNTIME_MODULE_H_
#define GAE_RUNTIME_MODULE_H_

extern "C" {
#ifdef __google_internal__
#include "php/main/php.h"
#else
#include "main/php.h"
#endif
}

extern zend_module_entry gae_runtime_module_entry;

// For each PECL extension that we implement in user PHP, we need to make sure
// that the function call 'extension_loaded('extension_name')' still returns
// true. To do that, we need to prepare fake zend_module_entry structures and
// add them to the startup routines.

extern zend_module_entry fake_memcache_module_entry;
extern zend_module_entry fake_memcached_module_entry;
extern zend_module_entry fake_curl_module_entry;

// Module globals structure
ZEND_BEGIN_MODULE_GLOBALS(gae_runtime_module)
    zval* recorded_errors_array;
    int disable_readonly_filesystem;
    int enable_curl_lite;
    bool enable_mail_replacement;
    int enable_gcs_stat_cache;
    const char* redirct_paths;
    bool vfs_initialized;
ZEND_END_MODULE_GLOBALS(gae_runtime_module)

namespace appengine {
// Check if a path should be redirected, will return true if the path should
// be redirected and will return the path for redirection in the new_path
// variable.
bool is_redirect_path(const char* path, char** new_path TSRMLS_DC);

// Retrieve the stream wrapper for the supplied path, taking into account that
// the path might be prepended by "redirect://" and need to be stripped.
php_stream_wrapper* get_correct_stream_wrapper(const char* path,
                                               char** path_for_open,
                                               int options TSRMLS_DC);
}  // namespace appengine

// The following method is defined with weak linkage in the PHP source so we can
// define it in our extension and have it called only when our extension is
// loaded.
extern "C"
int redirect_path_lookup(const char* path, char** new_path TSRMLS_DC);

#endif // GAE_RUNTIME_MODULE_H_
