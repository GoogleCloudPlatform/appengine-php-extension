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

#include "php_runtime_utils_stub.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

using std::string;
using std::stringstream;


#ifdef PHP_WIN32
#define strcasecmp _stricmp
#endif

namespace appengine {

void SplitString(const string& full,
                 const char* delim,
                 vector<string>* result) {
  size_t pos = 0;
  size_t found = string::npos;
  int delim_len = strlen(delim);
  vector<string> temp_vector;

  while ((found = full.find(delim, pos)) != string::npos) {
    const string ref = full.substr(pos, (found - pos));
    temp_vector.push_back(ref);
    pos = found + delim_len;
  }

  temp_vector.push_back(full.substr(pos));
  result->swap(temp_vector);
}

vector<string> SplitStringWithMaxSplit(const string& full,
                                       const char* delim,
                                       unsigned int max_split) {
  vector<string> result;
  appengine::SplitString(full, delim, &result);
  if (result.size() > max_split + 1) {
    vector<string> trailing(result.begin() + max_split, result.end());
    result[max_split] = appengine::JoinString(trailing, delim);
    result.resize(max_split + 1);
  }
  return result;
}

string JoinString(const vector<string>& parts, const char* delim) {
  string merged;
  for (int i = 0; i < parts.size(); ++i) {
    if (i != 0) {
      merged.append(delim);
    }
    merged.append(parts[i]);
  }
  return merged;
}

void TrimWhitespaceASCII(const string& input, string* output) {
  const char* space_chars = " \t\n\v\f\r";
  size_t left = input.find_first_not_of(space_chars);
  size_t right = input.find_last_not_of(space_chars);

  if (left == string::npos) {
    left = 0;
  }

  if (right == string::npos) {
    right = input.size();
  }

  output->assign(input.substr(left, right - left + 1));
}

bool StringCaseEqual(const string& str1, const string& str2) {
  return strcasecmp(str1.c_str(), str2.c_str()) == 0;
}

string StringPrintf(const char* format, ...) {
  int buf_size = 100;
  int len;
  char* buffer = new char[buf_size];
  std::string str;
  va_list args;

  va_start(args, format);
  len = vsnprintf(buffer, buf_size, format, args);
  va_end(args);
  if (len < buf_size) {
    // Everything fits into the initial buffer.
    str.assign(buffer, len);
  } else if (len >= buf_size) {
    // Not enough space. Enlarge buffer and try again.
    buf_size = len + 1;
    delete[] buffer;
    buffer = new char[buf_size];
    va_start(args, format);
    len = vsnprintf(buffer, buf_size, format, args);
    va_end(args);
    if (len > 0 && len < buf_size) {
      str.assign(buffer, len);
    }
  }

  delete[] buffer;

  // Will return empty string if there's any encoding error.
  return str;
}

string StrCat(const string &a, const string &b) {
  return a + b;
}

string StrCat(const string &a, int b) {
  return a + StringPrintf("%d", b);
}

string StrCat(const string &a, const string &b, const string &c) {
  return a + b + c;
}

static const char encodeLookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"
                                   "qrstuvwxyz0123456789+/";
static const char padCharacter = '=';

void EncodeBase64(const string& input, string* output) {
  output->clear();
  output->reserve(((input.size()/3) + (input.size() % 3 > 0)) * 4);
  unsigned long temp;
  string::const_iterator iter = input.begin();
  size_t triplet_count = input.length() / 3;
  for (size_t i = 0; i < triplet_count; ++i) {
    temp = (*iter++) << 16 | (*iter++) << 8 | (*iter++);
    output->append(1, encodeLookup[(temp & 0x00FC0000) >> 18]);
    output->append(1, encodeLookup[(temp & 0x0003F000) >> 12]);
    output->append(1, encodeLookup[(temp & 0x00000FC0) >> 6]);
    output->append(1, encodeLookup[(temp & 0x0000003F)]);
  }
  if (input.size() % 3 == 1) {
    temp = (*iter++) << 16;
    output->append(1, encodeLookup[(temp & 0x00FC0000) >> 18]);
    output->append(1, encodeLookup[(temp & 0x0003F000) >> 12]);
    output->append(2, padCharacter);
  } else if (input.size() % 3 == 2) {
    temp  = (*iter++) << 16 | (*iter++) << 8;
    output->append(1, encodeLookup[(temp & 0x00FC0000) >> 18]);
    output->append(1, encodeLookup[(temp & 0x0003F000) >> 12]);
    output->append(1, encodeLookup[(temp & 0x00000FC0) >> 6]);
    output->append(1, padCharacter);
  }
}

}  // namespace appengine
