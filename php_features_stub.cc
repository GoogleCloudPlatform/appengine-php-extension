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

// Author: marslan@google.com (Mars Lan)
//
// This file contains hard-coded values for the feature-guarding flags for
// the extension bundled with the SDK.

namespace fLB {

bool FLAGS_php_enable_direct_uploads = true;
bool FLAGS_php_enable_additional_cloud_storage_headers = true;
bool FLAGS_php_enable_tempnam = true;
bool FLAGS_php_enable_cross_stream_wrapper_rename = true;
bool FLAGS_php_enable_glob_replacement = true;
bool FLAGS_php_enforce_filesystem_readonly = true;
bool FLAGS_php_enable_mail_replacement = true;
bool FLAGS_php_remove_glob_stream_wrapper = true;
bool FLAGS_php_enable_gcs_stat_cache = true;
bool FLAGS_php_enable_php_output_stream = true;
bool FLAGS_php_unregister_unix_xport = false;
bool FLAGS_php_enable_syslog_replacement = true;
bool FLAGS_php_allow_file_redirect = false;
bool FLAGS_php_enable_gcs_default_keyword = true;

}  // namespace fLB
