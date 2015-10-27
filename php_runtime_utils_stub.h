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

#ifndef PHP_RUNTIME_UTILS_STUB_H_
#define PHP_RUNTIME_UTILS_STUB_H_

#include <string>
#include <vector>

using std::string;
using std::vector;


namespace appengine {

void SplitString(const string& fill,
                 const char* delim,
                 vector<string>* result);

vector<string> SplitStringWithMaxSplit(const string& full,
                                       const char* delim,
                                       unsigned int max_split);

string JoinString(const vector<string>& parts, const char* delim);

void TrimWhitespaceASCII(const string& input, string* output);

// Case insensitive equality comparison.
bool StringCaseEqual(const string& str1, const string& str2);

string StringPrintf(const char* format, ...);

string StrCat(const string &a, const string &b);
string StrCat(const string &a, int b);
string StrCat(const string &a, const string &b, const string &c);

void EncodeBase64(const string& input, string* output);

}  // namespace appengine

#endif // PHP_RUNTIME_UTILS_STUB_H_
