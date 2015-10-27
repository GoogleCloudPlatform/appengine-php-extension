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

#ifndef GAE_RUNTIME_MODULE_STUB_H_
#define GAE_RUNTIME_MODULE_STUB_H_

#include <iostream>  // NOLINT(readability/streams)
#include <string>

using std::string;

namespace base {
  enum LinkerInitialized { LINKER_INITIALIZED };
}

// Dummy Mutex class
class Mutex {
 public:
  Mutex() {}
  Mutex(base::LinkerInitialized x) {}  // NOLINT(runtime/explicit)
  ~Mutex() {}

  void Lock() {}
  void UnLock() {}
};

class MutexLock {
 public:
  MutexLock(Mutex *mutex) {}  // NOLINT
};

#define DEFINE_string(name, val, txt) \
    namespace fLS { \
      std::string FLAGS_##name = val; \
    } \
    using fLS::FLAGS_##name;

#define DEFINE_bool(name, val, txt) \
    namespace fLB { \
      bool FLAGS_##name = val; \
    } \
    using fLB::FLAGS_##name;

#define DECLARE_bool(name) \
    namespace fLB { \
      extern bool FLAGS_##name; \
    } \
    using fLB::FLAGS_##name;

#define CHECK(var) assert(var)

#define VLOG(level) std::cerr

#endif // GAE_RUNTIME_MODULE_STUB_H_
