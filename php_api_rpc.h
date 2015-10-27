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
#ifndef PHP_API_RPC_H_
#define PHP_API_RPC_H_

#include <string>

typedef long long int64;

using std::string;

namespace appengine {

class RuntimeModule;

class PhpApiRpc {
 public:
  enum Error {
    OK = 0,
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

  PhpApiRpc()
      : error_(OK),
        cpu_usage_(0) {
  }

  Error error() const {
    return error_;
  }
  void set_error(Error error) {
    error_ = error;
  }

  const string& error_detail() const {
    return error_detail_;
  }
  void set_error_detail(const string& error_detail) {
    error_detail_ = error_detail;
  }

  int app_error() const {
    return app_error_;
  }
  void set_app_error(int app_error) {
    app_error_ = app_error;
  }

  int64 cpu_usage() const {
    return cpu_usage_;
  }
  void set_cpu_usage(int64 cpu_usage) {
    cpu_usage_ = cpu_usage;
  }

  const string& response_pb() const {
    return response_pb_;
  }
  void set_response_pb(const string& response_pb) {
    response_pb_ = response_pb;
  }

 private:
  string request_id_;
  string response_pb_;

  Error error_;
  string error_detail_;
  int app_error_;

  int64 cpu_usage_;
};

}  // namespace appengine

#endif // PHP_API_RPC_H_
