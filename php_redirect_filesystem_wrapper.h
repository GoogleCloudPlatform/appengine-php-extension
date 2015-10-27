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
#ifndef PHP_REDIRECT_FILESYSTEM_WRAPPER_H_
#define PHP_REDIRECT_FILESYSTEM_WRAPPER_H_

extern "C" {
#ifdef __google_internal__
#include "php/main/php.h"
#include "php/main/php_streams.h"
#else
#include "main/php.h"
#include "main/php_streams.h"
#endif
}  // extern "C"

namespace appengine {

extern php_stream_wrapper php_redirect_stream_wrapper;

}  // namespace appengine

#endif // PHP_REDIRECT_FILESYSTEM_WRAPPER_H_
