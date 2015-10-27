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

#ifndef PHP_CONSTANTS_H_
#define PHP_CONSTANTS_H_

namespace appengine {
// RPC values taken from APIRpc - used here so we don't need to pull in APIRpc
// when testing using gmock.
enum RPC_ERROR_CODES {
  RPC_OK = 0,
  RPC_FAILED,
  CALL_NOT_FOUND,
  ARGUMENT_ERROR,
  DEADLINE_EXCEEDED,
  CANCELLED,
  APPLICATION_ERROR,
  OTHER_ERROR,
  OVER_QUOTA,
  REQUEST_TOO_LARGE,
  CAPABILITY_DISABLED,
  FEATURE_DISABLED,
  RESPONSE_TOO_LARGE
};

// The name of the php make_call hook
static const char kMakeApiCallName[] = "make_call";

// The values returned from RPC calls in the hash table.
static const char kErrorCodeName[] = "error";
static const char kApplicationErrorCodeName[] = "application_error";
static const char kApplicationErrorDetailName[] = "error_detail";
static const char kResultStringName[] = "result_string";
static const char kCpuUsageName[] = "cpu_usage_mcycles";

// Taken from //webutil/http/httpresponse.h
enum ResponseCode {
  RC_REQUEST_OK = 200,
  RC_NOT_FOUND  = 404,  // Not found
  RC_ERROR      = 500,  // Internal server error
};

}  // namespace appengine

#endif // PHP_CONSTANTS_H_
