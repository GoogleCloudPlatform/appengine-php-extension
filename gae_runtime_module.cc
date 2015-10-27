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

#include "gae_runtime_module.h"

#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "php_constants.h"
#include "php_stream_wrapper.h"
#include "php_readonly_filesystem_wrapper.h"
#include "php_redirect_filesystem_wrapper.h"
#include "urlfetch_stream_wrapper.h"

#include "gae_runtime_module_stub.h"
#include "php_rpc_utils_stub.h"
#include "php_runtime_utils_stub.h"
#include "php_runtime_sapi_stub.h"

extern "C" {
#ifdef __google_internal__
#include "php/main/php.h"
#include "php/main/php_ini.h"
#include "php/main/SAPI.h"
#include "php/main/php_streams.h"
#include "php/main/rfc1867.h"
#include "php/ext/standard/php_filestat.h"
#include "php/ext/sockets/php_sockets.h"
#include "php/ext/spl/spl_exceptions.h"
#include "php/ext/standard/file.h"
#include "php/ext/standard/info.h"
#include "php/Zend/zend_API.h"
#include "php/Zend/zend_exceptions.h"
#include "php/Zend/zend_hash.h"
#include "php/Zend/zend_interfaces.h"
#else
#include "main/php.h"
#include "main/php_ini.h"
#include "main/php_streams.h"
#include "main/SAPI.h"
#include "main/rfc1867.h"
#include "ext/standard/php_filestat.h"
#include "ext/sockets/php_sockets.h"
#include "ext/spl/spl_exceptions.h"
#include "ext/standard/file.h"
#include "ext/standard/info.h"
#include "Zend/zend_API.h"
#include "Zend/zend_exceptions.h"
#include "Zend/zend_hash.h"
#include "Zend/zend_interfaces.h"
#endif
}

ZEND_DECLARE_MODULE_GLOBALS(gae_runtime_module)

#ifdef ZTS
#define GAERT_G(v) TSRMG(gae_runtime_module_globals_id, \
                         zend_gae_runtime_module_globals*, \
                         v)
#else
#define GAERT_G(v) (gae_runtime_module_globals.v)
#endif

using appengine::JoinString;
using appengine::SplitString;
using appengine::SplitStringWithMaxSplit;
using appengine::TrimWhitespaceASCII;
using appengine::urlfetch_stream_wrapper_module_entry;

using std::pair;
using std::set;
using std::string;
using std::vector;

#pragma GCC diagnostic ignored "-Wwritable-strings"  // PHP APIs not const safe.

DEFINE_string(php_delete_functions,
              "dl, mb_send_mail",
              "Comma seperated list of functions to delete from the PHP global "
              "function table. This will result in these functions being "
              "undefined. Use php_disable_functions to disable functions but "
              "leave them defined.");

DEFINE_string(php_disable_functions,
              "diskfreespace, disk_free_space, disk_total_space, "
              "escapeshellarg, escapeshellcmd, exec, "
              "highlight_file, link, lchgrp, lchown, passthru, "
              "pclose, popen, proc_close, proc_get_status, proc_nice, "
              "proc_open, proc_terminate, set_time_limit, shell_exec, "
              "show_source, symlink, system",
              "Comma separated list of functions to disable.");

DEFINE_string(php_disable_classes,
              "",
              "Comma separated list of classes to disable.");

DEFINE_string(php_unregister_streams,
              "php, data",
              "Comma seperated list of streams to unregister, making them "
              "unavailable.");

DEFINE_string(php_unregister_xports,
              "sslv2, sslv3, tls, udg, udp",
              "Comma seperated list of stream transports to unregister, making "
              "them unavailable.");

DEFINE_string(php_additional_soft_disable_functions,
              "",
              "Comma separated list of functions to be added to the built in "
              "list of disabled functions that will be disabled unless "
              "the user explicitly enables them in their user.ini file.");

DECLARE_bool(php_enable_direct_uploads);
DECLARE_bool(php_enable_additional_cloud_storage_headers);
DECLARE_bool(php_enable_tempnam);
DECLARE_bool(php_enable_cross_stream_wrapper_rename);
DECLARE_bool(php_enable_glob_replacement);
DECLARE_bool(php_enforce_filesystem_readonly);
DECLARE_bool(php_enable_mail_replacement);
DECLARE_bool(php_remove_glob_stream_wrapper);
DECLARE_bool(php_enable_gcs_stat_cache);
DECLARE_bool(php_unregister_unix_xport);
DECLARE_bool(php_enable_syslog_replacement);
DECLARE_bool(php_allow_file_redirect);
DECLARE_bool(php_enable_gcs_default_keyword);

DECLARE_bool(enable_socket_api);

using appengine::php_input_stream_wrapper;
using appengine::php_redirect_stream_wrapper;
using appengine::PhpApiRpc;
using appengine::PhpRpcUtils;
using appengine::StringCaseEqual;

// Keep track of user supplied ini variables, which can be defined in a file
// names 'php.ini' in the application root.
static HashTable* user_ini_hash_table = NULL;

// Keep track of redirect path mapping, which can be supplied in the users
// php.ini file.
static HashTable* redirect_path_hash_table = NULL;

// Keep track of memory we've created disabling functions, so we can clean it
// up on module exit
static vector<char*>* disabled_function_names = NULL;

// Keep track of memory we've created for overridden INI values.
static vector<char*>* overriden_ini_values = NULL;

// Mutex to ensure that only one request can be initialized at a time.
static Mutex request_init_mutex(base::LINKER_INITIALIZED);

static Mutex redirect_path_ht_mutex(base::LINKER_INITIALIZED);

// Comma separated list of default soft disable functions - These functions will
// be disabled unless the user enables them in the applications php.ini by
// adding them to the google_app_engine.enable_functions setting.
static const char kSoftDisableFunctions[] = "phpinfo, getmypid, getmyuid, "
    "gc_collect_cycles, gc_enable, gc_disable, gc_enabled, php_uname, "
    "php_sapi_name, getrusage, getmyinode, getmygid, get_current_user,"
    "libxml_disable_entity_loader";

// Comma separated list of socket related functions that should only be
// available to apps that have socket access. The list is taken from
// http://www.php.net/manual/en/ref.network.php sans gethostname().
static const char kSocketFunctions[] = "checkdnsrr, dns_check_record, "
    "dns_get_mx, dns_get_record, fsockopen, gethostbyaddr, gethostbyname, "
    "gethostbynamel, getmxrr, getprotobyname, getprotobynumber, getservbyname, "
    "getservbyport, pfsockopen, socket_get_status, socket_set_blocking, "
    "socket_set_timeout";

// Comma separated list of FTP related functions that should only be available
// to apps that have socket access. This list is taken from
// http://www.php.net/manual/en/ref.ftp.php
static const char kFtpFunctions[] = "ftp_alloc, ftp_cdup, ftp_chdir, "
    "ftp_chmod, ftp_close, ftp_connect, ftp_delete, ftp_exec, ftp_fget, "
    "ftp_fput, ftp_get_option, ftp_get, ftp_login, ftp_mdtm, ftp_mkdir, "
    "ftp_nb_continue, ftp_nb_fget, ftp_nb_fput, ftp_nb_get, ftp_nb_put, "
    "ftp_nlist, ftp_pasv, ftp_put, ftp_pwd, ftp_quit, ftp_raw, ftp_rawlist, "
    "ftp_rename, ftp_rmdir, ftp_set_option, ftp_site, ftp_size, "
    "ftp_ssl_connect, ftp_systype";

static const char kEnableFunctions[] = "google_app_engine.enable_functions";
static const char kGoogleStorageProtocol[] = "gs";
static const char kGlobFunctionName[] =
    "google\\appengine\\runtime\\Glob::doGlob";
static const char kTempnamFunctionName[] =
    "google\\appengine\\runtime\\SplOverride::tempnam";
static const char kSysGetTempDirFunctionName[] =
    "google\\appengine\\runtime\\SplOverride::sys_get_temp_dir";
static const char kMailFunctionName[] =
    "google\\appengine\\runtime\\Mail::sendMail";
static const char kClearGcsStatCacheFunctionName[] =
    "google\\appengine\\ext\\cloud_storage_streams\\"
    "CloudStorageClient::clearStatCache";
static const char kGetHostnameFunctionName[] =
    "google\\appengine\\runtime\\SplOverride::gethostname";
static const char kMoveUploadedFileFunctionName[] =
    "google\\appengine\\runtime\\SplOverride::move_uploaded_file";
static const char kLogFunctionName[] =
    "google\\appengine\\api\\log\\LogService::log";
static const char kRedirectProtocol[] = "redirect";
static const char kRedirectPrependString[] = "redirect://";
static const char kTilde[] = "~";
static const char kBaseDirectory[] = "~/";
static const char kVfsPrefix[] = "vfs://";
static const char kVirtualFileSystemInitializeFunctionName[] =
    "google\\appengine\\runtime\\VirtualFileSystem::getInstance";
static const char kVirtualFileSystemIntiailizeMethodName[] = "initialize";

static const int kSyslogPriorityMask = 0x07;
// Map syslog severity levels to appengine app_log levels.
const int kSyslogPriorityMap[] = {4, 4, 4, 3, 2, 1, 1, 0};

static void replace_builtin_functions(INIT_FUNC_ARGS);

static bool initialize_virtual_filesystem(TSRMLS_D);

static int get_user_ini_string(const char* key_name, const char** result);

PHP_FUNCTION(memory_tmpfile);

// Dummy function that displays that this function has been soft disabled
ZEND_FUNCTION(display_soft_disabled_function) {
  zend_error(E_WARNING, "%s() has been disabled for security reasons. "
      "It can be re-enabled by adding it to the %s ini variable in your "
      "applications php.ini", get_active_function_name(TSRMLS_C),
      kEnableFunctions);
}

static zend_function_entry soft_disabled_function_table[] = {
    ZEND_FE(display_soft_disabled_function, NULL)
    ZEND_FE_END
};

// Dummy function that displays that this socket functions are not available
// for this application
ZEND_FUNCTION(display_socket_disabled_function) {
  zend_error(E_WARNING, "%s() has been disabled for your application.",
             get_active_function_name(TSRMLS_C));
}

static zend_function_entry socket_disabled_function_table[] = {
    ZEND_FE(display_socket_disabled_function, NULL)
    ZEND_FE_END
};

// Callback function to free up persistent memory from the redirect hash table.
void free_redirect_destination(char** str_p) {
  pefree(*str_p, 1);
}

int redirect_path_lookup(const char* path, char** new_path TSRMLS_DC) {
  char* tmp_path;
  if (appengine::is_redirect_path(path, &tmp_path TSRMLS_CC)) {
    *new_path = tmp_path;
    return 1;
  }
  return 0;
}

// Soft disable the supplied function.
static int replace_function(const char* function_name,
                                 zend_function_entry* replacement TSRMLS_DC) {
  if (zend_hash_del(CG(function_table),
                    function_name,
                    strlen(function_name) + 1) == FAILURE) {
    return FAILURE;
  }

  char* name_copy = pestrdup(function_name, 1);

  CHECK(disabled_function_names);
  disabled_function_names->push_back(name_copy);

  replacement[0].fname = name_copy;

  return zend_register_functions(NULL,
                                 replacement,
                                 CG(function_table),
                                 MODULE_PERSISTENT TSRMLS_CC);
}

// Delete functions from the compiler global function table. Typically we
// undefine functions that we want to re-implement in an appengine specific way,
// such as mail.
static void delete_functions(INIT_FUNC_ARGS) {
  if (!FLAGS_php_delete_functions.empty()) {
    vector<string> functions;
    SplitString(FLAGS_php_delete_functions, ",", &functions);
    for (int i = 0; i < functions.size() ; ++i) {
      TrimWhitespaceASCII(functions[i], &functions[i]);
      if (!functions[i].empty()) {
        zend_hash_del(CG(function_table),
                      functions[i].c_str(),
                      functions[i].length() + 1);
      }
    }
  }
}

// Remove streams from the protocol table. This makes these streams unavailable.
// Typically these are removed due to potential security vulnerabilities.
static void unregister_streams(INIT_FUNC_ARGS) {
  if (!FLAGS_php_unregister_streams.empty()) {
    vector<string> streams;
    SplitString(FLAGS_php_unregister_streams, ",", &streams);
    if (FLAGS_php_remove_glob_stream_wrapper) {
      streams.push_back("glob");
    }
    for (int i = 0; i < streams.size(); ++i) {
      string& stream_name = streams[i];
      TrimWhitespaceASCII(stream_name, &stream_name);
      if (!stream_name.empty()) {
        php_unregister_url_stream_wrapper(
            const_cast<char*>(stream_name.c_str()) TSRMLS_CC);
      }
    }
  }
}

// Remove stream transports that are not supported from the transport table.
static void unregister_stream_xports(INIT_FUNC_ARGS) {
  if (!FLAGS_php_unregister_xports.empty()) {
    vector<string> xports;
    SplitString(FLAGS_php_unregister_xports, ",", &xports);
    for (int i = 0; i < xports.size(); ++i) {
      string& xport_name = xports[i];
      TrimWhitespaceASCII(xport_name, &xport_name);
      if (!xport_name.empty()) {
        php_stream_xport_unregister(
            const_cast<char*>(xport_name.c_str()) TSRMLS_CC);
      }
    }
  }

  if (FLAGS_php_unregister_unix_xport) {
      php_stream_xport_unregister("unix" TSRMLS_CC);
  }
}

// Disable socket related transports and functions, if required.
static void disable_socket_functions(INIT_FUNC_ARGS) {
  // Sockets are only enabled if the borg flag is set (and ultimately if
  // billing is enabled).
  if (FLAGS_enable_socket_api) {
    return;
  }
  // Disable the transports
  php_stream_xport_unregister("ssl" TSRMLS_CC);
  php_stream_xport_unregister("tcp" TSRMLS_CC);

  // Disable all of the functions in the socket extension.
  zend_module_entry* sockets_module;
  if (zend_hash_find(&module_registry, "sockets", sizeof("sockets"),
                     reinterpret_cast<void**>(&sockets_module)) == SUCCESS &&
      sockets_module != NULL && sockets_module->functions != NULL) {
    const zend_function_entry* function_ptr = sockets_module->functions;
    while (function_ptr->fname != NULL) {
      replace_function(function_ptr->fname,
                       socket_disabled_function_table TSRMLS_CC);
      ++function_ptr;
    }
  }

  // Disable all of the functions in the kSocketFunction list.
  vector<string> socket_functions_list;
  SplitString(kSocketFunctions, ",", &socket_functions_list);
  for (int i = 0; i < socket_functions_list.size(); ++i) {
    TrimWhitespaceASCII(socket_functions_list[i],
                        &socket_functions_list[i]);
    replace_function(socket_functions_list[i].c_str(),
                     socket_disabled_function_table TSRMLS_CC);
  }
  // Disable all of the functions in the kFtpFunctions list.
  SplitString(kFtpFunctions, ",", &socket_functions_list);
  for (int i = 0; i < socket_functions_list.size(); ++i) {
    TrimWhitespaceASCII(socket_functions_list[i],
                        &socket_functions_list[i]);
    replace_function(socket_functions_list[i].c_str(),
                     socket_disabled_function_table TSRMLS_CC);
  }
}

static void gae_runtime_module_init_globals(
    zend_gae_runtime_module_globals* module_globals) {
  module_globals->recorded_errors_array = NULL;
  module_globals->disable_readonly_filesystem = 0;
  module_globals->enable_curl_lite = 0;
  module_globals->enable_mail_replacement = FLAGS_php_enable_mail_replacement;
  module_globals->enable_gcs_stat_cache = FLAGS_php_enable_gcs_stat_cache;
  module_globals->vfs_initialized = false;
}

static void zend_update_ini_entry(
    const char* key, const char* value TSRMLS_DC) {

  zend_ini_entry *entry;
  if (zend_hash_find(EG(ini_directives),
                     key,
                     strlen(key) + 1,
                     reinterpret_cast<void **>(&entry)) == FAILURE) {
    php_error(E_ERROR, "Fail to find existing ini directive %s.", key);
    return;
  }

  char* duplicate = pestrdup(value, 1);
  overriden_ini_values->push_back(duplicate);
  entry->value = duplicate;
  entry->value_length = strlen(duplicate) + 1;
}

static void zend_merge_with_user_ini_string(
    const char* key_name, const string& value TSRMLS_DC) {
  vector<string> strings;
  strings.push_back(value);

  const char* ini_value;
  if (get_user_ini_string(key_name, &ini_value) == SUCCESS) {
    strings.push_back(ini_value);
  }

  set<string> string_set;
  for (int i = 0; i < strings.size(); ++i) {
    vector<string> splited;
    SplitString(strings[i], ",", &splited);
    for (int i = 0; i < splited.size(); ++i) {
      TrimWhitespaceASCII(splited[i], &splited[i]);
      string_set.insert(splited[i]);
    }
  }

  string merged = JoinString(
      vector<string>(string_set.begin(), string_set.end()), ",");
  zend_update_ini_entry(key_name, merged.c_str() TSRMLS_CC);
}

static void override_ini_values(INIT_FUNC_ARGS) {
  if (!FLAGS_php_enable_tempnam) {
    if (!FLAGS_php_disable_functions.empty()) {
      FLAGS_php_disable_functions.append(", ");
    }
    FLAGS_php_disable_functions.append("tempnam");
  }

  zend_merge_with_user_ini_string("disable_functions",
                                  FLAGS_php_disable_functions TSRMLS_CC);
  zend_merge_with_user_ini_string("disable_classes",
                                  FLAGS_php_disable_classes TSRMLS_CC);
  zend_update_ini_entry("file_uploads",
                        FLAGS_php_enable_direct_uploads ? "1" : "0" TSRMLS_CC);
  zend_update_ini_entry("google_app_engine.direct_file_upload",
                        FLAGS_php_enable_direct_uploads ? "1" : "0" TSRMLS_CC);

  zend_update_ini_entry(
      "google_app_engine.enable_additional_cloud_storage_headers",
      FLAGS_php_enable_additional_cloud_storage_headers ? "1" : "0" TSRMLS_CC);

  zend_update_ini_entry(
      "google_app_engine.enable_gcs_stat_cache",
      FLAGS_php_enable_gcs_stat_cache ? "1" : "0" TSRMLS_CC);

  zend_update_ini_entry(
      "google_app_engine.gcs_default_keyword",
      FLAGS_php_enable_gcs_default_keyword ? "1" : "0" TSRMLS_CC);
}

static void load_user_ini(INIT_FUNC_ARGS) {
  CHECK(user_ini_hash_table);
  // Read in the users php.ini file
  const char* const application_basedir =
      appengine::PhpRuntimeSapi::GetApplicationBasedir();

  if (!application_basedir) {
    php_error_docref(NULL TSRMLS_CC, E_ERROR,
        "Unable to load users's php.ini due to missing application base dir.");
    return;
  }

  php_parse_user_ini_file(application_basedir,
                          "php.ini",
                          user_ini_hash_table TSRMLS_CC);
}

static int get_user_ini_string(const char* key_name, const char** result) {
  CHECK(user_ini_hash_table);
  zval* tmp;
  if (zend_hash_find(user_ini_hash_table,
                     key_name,
                     strlen(key_name) + 1,
                     reinterpret_cast<void**>(&tmp)) == FAILURE) {
    *result = NULL;
    return FAILURE;
  }
  *result = Z_STRVAL_P(tmp);
  return SUCCESS;
}

static void soft_disable_functions(INIT_FUNC_ARGS) {
  vector<string> soft_disable_functions_list;
  SplitString(kSoftDisableFunctions, ",", &soft_disable_functions_list);
  SplitString(FLAGS_php_additional_soft_disable_functions,
              ",",
              &soft_disable_functions_list);

  vector<string> user_enable_functions_list;
  const char* enabled_functions;

  if (get_user_ini_string(kEnableFunctions, &enabled_functions) == SUCCESS) {
    SplitString(enabled_functions, ",", &user_enable_functions_list);
  }

  for (int i = 0; i < soft_disable_functions_list.size(); ++i) {
    TrimWhitespaceASCII(soft_disable_functions_list[i],
                        &soft_disable_functions_list[i]);
  }

  set<string> disable_functions(soft_disable_functions_list.begin(),
                                soft_disable_functions_list.end());

  for (int i = 0; i < user_enable_functions_list.size(); ++i) {
    TrimWhitespaceASCII(user_enable_functions_list[i],
                        &user_enable_functions_list[i]);
    disable_functions.erase(user_enable_functions_list[i]);
  }

  for (set<string>::iterator it = disable_functions.begin();
       it != disable_functions.end();
       ++it) {
    replace_function((*it).c_str(), soft_disabled_function_table TSRMLS_CC);
  }
}

static void enable_allowed_include_streams(INIT_FUNC_ARGS) {
  // If the user has declared buckets that can be included then enable include
  // without them having to specifically enable the "gs" stream.
  bool enable_gs_include = false;
  const char* allowed_buckets;
  if (get_user_ini_string("google_app_engine.allow_include_gs_buckets",
                          &allowed_buckets) == SUCCESS) {
    if (strlen(allowed_buckets) > 0) {
      enable_gs_include = true;
    }
    REGISTER_STRINGL_CONSTANT("GAE_INCLUDE_GS_BUCKETS",
                              const_cast<char*>(allowed_buckets),
                              strlen(allowed_buckets),
                              CONST_CS | CONST_PERSISTENT);
  } else {
    REGISTER_STRING_CONSTANT("GAE_INCLUDE_GS_BUCKETS",
                             "",
                             CONST_CS | CONST_PERSISTENT);
  }
  // As the gs:// stream is defined in user space, register a constant here
  // that we check in setup.php to configure the access.
  REGISTER_LONG_CONSTANT("GAE_INCLUDE_REQUIRE_GS_STREAMS",
                         enable_gs_include ? 1 : 0,
                         CONST_CS | CONST_PERSISTENT);
}

static void allocate_static_resources(INIT_FUNC_ARGS) {
  if (user_ini_hash_table == NULL) {
    user_ini_hash_table = reinterpret_cast<HashTable*>(
        pemalloc(sizeof(HashTable), 1));
    zend_hash_init(user_ini_hash_table,
                   0,
                   NULL,
                   (dtor_func_t) config_zval_dtor,
                   1);
  }
  if (redirect_path_hash_table == NULL) {
    redirect_path_hash_table = reinterpret_cast<HashTable*>(
        pemalloc(sizeof(HashTable), 1));
    zend_hash_init(redirect_path_hash_table,
                   16,
                   NULL,
                   reinterpret_cast<dtor_func_t>(free_redirect_destination),
                   1);
  }
  if (disabled_function_names == NULL) {
    disabled_function_names = new vector<char*>();
  }
  if (overriden_ini_values == NULL) {
    overriden_ini_values = new vector<char*>();
  }
}

template<typename T>
static bool sort_string_key_lengths(const T& s1, const T& s2) {
  return s1.first.length() > s2.first.length();
}

static void load_redirect_paths(INIT_FUNC_ARGS) {
  vector<pair<string, string> > split_paths;
  vector<string> path_pairs;
  SplitString(GAERT_G(redirct_paths), ";", &path_pairs);

  for (int i = 0; i < path_pairs.size(); ++i) {
    TrimWhitespaceASCII(path_pairs[i], &path_pairs[i]);
    if (!path_pairs[i].empty()) {
      vector<string> paths = SplitStringWithMaxSplit(path_pairs[i], ":", 1);
      if (paths.size() == 2) {
        TrimWhitespaceASCII(paths[0], &paths[0]);
        TrimWhitespaceASCII(paths[1], &paths[1]);
        if (paths[0].length() > 0 && paths[1].length() > 0) {
          // Do not allow users to redirect the base directory, as it stops the
          // app from working.
          if (paths[0] != kBaseDirectory) {
            split_paths.push_back(make_pair(paths[0], paths[1]));
          } else {
            php_error_docref(NULL TSRMLS_CC, E_ERROR,
                "Cannot redirect the path ~/, redirection ignored.");
          }
        } else {
          php_error_docref(NULL TSRMLS_CC, E_ERROR,
              "Invalid redirect from_path(%s) or to_path(%s)",
               paths[0].c_str(),
               paths[1].c_str());
        }
      } else {
         php_error_docref(NULL TSRMLS_CC, E_ERROR,
             "Invalid redirect path pair: %s", path_pairs[i].c_str());
      }
    }
  }

  // Exapand any redirect paths that start with ~/ to be the applications
  // base directory.
  const char* const application_basedir =
      appengine::PhpRuntimeSapi::GetApplicationBasedir();

  for (int i = 0; i < split_paths.size(); ++i) {
    if (split_paths[i].first.find(kBaseDirectory) == 0) {
      split_paths[i].first.replace(0,
                                   strlen(kTilde),
                                   application_basedir);
    }
  }


  // Sort from longest path to shortest, so that when matching redirect paths
  // we will match the longest matching path first.
  sort(split_paths.begin(),
       split_paths.end(),
       sort_string_key_lengths<pair<string, string> >);

  for (int i = 0; i < split_paths.size(); ++i) {
    const string& key = split_paths[i].first;
    char* data = pestrdup(split_paths[i].second.c_str(), 1);
    zend_hash_add(redirect_path_hash_table,
                  key.c_str(),
                  key.length() + 1,
                  reinterpret_cast<void*>(&data),
                  sizeof(char*),
                  NULL);
  }
}

static void release_static_resources(TSRMLS_D) {
  if (user_ini_hash_table) {
    zend_hash_destroy(user_ini_hash_table);
    free(user_ini_hash_table);
    user_ini_hash_table = NULL;
  }
  if (disabled_function_names) {
    for (int i = 0; i < disabled_function_names->size(); ++i) {
      pefree(disabled_function_names->at(i), 1);
    }
    delete disabled_function_names;
    disabled_function_names = NULL;
  }
  if (overriden_ini_values) {
    for (int i = 0; i < overriden_ini_values->size(); ++i) {
      pefree(overriden_ini_values->at(i), 1);
    }
    delete overriden_ini_values;
    overriden_ini_values = NULL;
  }
  if (redirect_path_hash_table) {
    zend_hash_destroy(redirect_path_hash_table);
    free(redirect_path_hash_table);
    redirect_path_hash_table = NULL;
  }
}

static void update_ca_bundle_local_path(INIT_FUNC_ARGS) {
  const char* const cainfo_ini_name = "curl.cainfo";
  const char* ini_value = zend_ini_string(const_cast<char*>(cainfo_ini_name),
                                          strlen(cainfo_ini_name) + 1,
                                          0);

  if (ini_value != NULL) {
    if (ini_value[0] == '~' && ini_value[1] == '/') {
      const char* const application_basedir =
          appengine::PhpRuntimeSapi::GetApplicationBasedir();
      string new_path = application_basedir + string(ini_value + 1);
      zend_update_ini_entry(cainfo_ini_name, new_path.c_str() TSRMLS_CC);
    }
  }
}

bool appengine::is_redirect_path(const char* path, char** new_path TSRMLS_DC) {
  HashPosition pos;

  MutexLock l(&redirect_path_ht_mutex);

  for (zend_hash_internal_pointer_reset_ex(redirect_path_hash_table, &pos);
      zend_hash_has_more_elements_ex(redirect_path_hash_table, &pos) == SUCCESS;
      zend_hash_move_forward_ex(redirect_path_hash_table, &pos)) {
    char* key;
    uint keylen;
    ulong idx;

    if (zend_hash_get_current_key_ex(redirect_path_hash_table,
                                     &key,
                                     &keylen,
                                     &idx,
                                     0,
                                     &pos) == HASH_KEY_IS_STRING) {
      // TODO(slangley): Should be case insensitive?
      if (strncmp(key, path, keylen-1) == 0) {
        char** data;
        if (zend_hash_get_current_data_ex(redirect_path_hash_table,
                                          reinterpret_cast<void**>(&data),
                                          &pos) == SUCCESS) {
          // We have a match, take a copy and return it.
          string updated_path = path;
          string replacement_prefix = *data;
          updated_path.replace(0, keylen-1, replacement_prefix);
          updated_path.insert(0, kRedirectPrependString);
          *new_path = estrdup(updated_path.c_str());
          return true;
        }
      }
    }
  }
  return false;
}

php_stream_wrapper* appengine::get_correct_stream_wrapper(const char* path,
    char** path_for_open, int options TSRMLS_DC) {
  if (!strncmp(path, kRedirectPrependString, strlen(kRedirectPrependString))) {
    const char* actual_path = path + strlen(kRedirectPrependString);
    if (strncmp(actual_path, kVfsPrefix, strlen(kVfsPrefix)) == 0) {
      if (!GAERT_G(vfs_initialized)) {
        GAERT_G(vfs_initialized) = initialize_virtual_filesystem(TSRMLS_C);
      }
    }
    return php_stream_locate_url_wrapper(actual_path,
                                         path_for_open,
                                         options TSRMLS_CC);
  } else {
    return php_stream_locate_url_wrapper(path,
                                         path_for_open,
                                         options TSRMLS_CC);
  }
}


bool initialize_virtual_filesystem(TSRMLS_D) {
  bool result = false;
  zval* z_function_name = NULL;
  zval* z_retval = NULL;

  MAKE_STD_ZVAL(z_function_name);
  MAKE_STD_ZVAL(z_retval);
  ZVAL_STRING(z_function_name, kVirtualFileSystemInitializeFunctionName, 0);

  // Call VirtualFileSystem::getInstance() and store the resulting object in
  // z_retval.
  if (call_user_function(EG(function_table),
                         NULL,
                         z_function_name,
                         z_retval,
                         0,
                         NULL TSRMLS_CC) == SUCCESS) {
    zval* z_method_retval = NULL;

    MAKE_STD_ZVAL(z_method_retval);
    ZVAL_STRING(z_function_name, kVirtualFileSystemIntiailizeMethodName, 0);
    // Call the initialize() method on the VirtualFileSystem, which is stored in
    // the return value of the previous call.
    if (call_user_function(NULL,
                           &z_retval,
                           z_function_name,
                           z_method_retval,
                           0,
                           NULL TSRMLS_CC) == SUCCESS) {
      result = true;
      if (z_method_retval) {
        zval_ptr_dtor(&z_method_retval);
      }
    } else {
      php_error_docref(NULL TSRMLS_CC, E_WARNING,
                       "Unable to initialize virtial filesystem calling %s()",
                       kVirtualFileSystemIntiailizeMethodName);
    }
  } else {
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                     "Unable to call %s()",
                     kVirtualFileSystemInitializeFunctionName);
  }
  if (z_retval) {
    zval_ptr_dtor(&z_retval);
  }
  return result;
}


#define GAE_INI_ENTRY(name, default) \
    PHP_INI_ENTRY(name, default, PHP_INI_PERDIR, NULL)
#define GAE_INI_ENTRY_SYSTEM(name, default) \
    PHP_INI_ENTRY(name, default,  PHP_INI_SYSTEM, NULL)
#define GAE_STR_INI_ENTRY(name, default, access, var) \
    STD_PHP_INI_ENTRY(name, default, access, OnUpdateString , var, \
                      zend_gae_runtime_module_globals, \
                      gae_runtime_module_globals)
#define GAE_BOOL_INI_ENTRY(name, default, access, var) \
    STD_PHP_INI_BOOLEAN(name, default, access, OnUpdateBool, var, \
                        zend_gae_runtime_module_globals, \
                        gae_runtime_module_globals)

// Note: The way these macros expand, we cannot use const_cast<char*>(kName)
// as it results in sizeof(char*) being used to determine the name size, which
// is wrong.
PHP_INI_BEGIN()
  GAE_INI_ENTRY("google_app_engine.enable_functions", "")
  GAE_INI_ENTRY("google_app_engine.allow_include_gs_buckets", "")
  GAE_INI_ENTRY_SYSTEM("google_app_engine.direct_file_upload", "0")
  GAE_INI_ENTRY_SYSTEM("google_app_engine.gcs_default_keyword", "0")
  GAE_INI_ENTRY_SYSTEM(
    "google_app_engine.enable_additional_cloud_storage_headers", "0")
  GAE_STR_INI_ENTRY("google_app_engine.redirect_paths",
                    "",
                    PHP_INI_SYSTEM,
                    redirct_paths)
  GAE_BOOL_INI_ENTRY("google_app_engine.disable_readonly_filesystem",
                     "0",
                     PHP_INI_SYSTEM,
                     disable_readonly_filesystem)
  GAE_BOOL_INI_ENTRY("google_app_engine.enable_curl_lite",
                     "0",
                     PHP_INI_SYSTEM,
                     enable_curl_lite)
  GAE_BOOL_INI_ENTRY("google_app_engine.enable_gcs_stat_cache",
                     "0",
                     PHP_INI_SYSTEM,
                     enable_gcs_stat_cache)
PHP_INI_END()

// Module initialization function.
static PHP_MINIT_FUNCTION(gae_runtime_module) {
  ZEND_INIT_MODULE_GLOBALS(gae_runtime_module,
                           gae_runtime_module_init_globals,
                           NULL);
  REGISTER_INI_ENTRIES();

  allocate_static_resources(INIT_FUNC_ARGS_PASSTHRU);
  load_user_ini(INIT_FUNC_ARGS_PASSTHRU);
  override_ini_values(INIT_FUNC_ARGS_PASSTHRU);
  delete_functions(INIT_FUNC_ARGS_PASSTHRU);
  unregister_streams(INIT_FUNC_ARGS_PASSTHRU);
  unregister_stream_xports(INIT_FUNC_ARGS_PASSTHRU);
  soft_disable_functions(INIT_FUNC_ARGS_PASSTHRU);
  enable_allowed_include_streams(INIT_FUNC_ARGS_PASSTHRU);
  disable_socket_functions(INIT_FUNC_ARGS_PASSTHRU);
  replace_builtin_functions(INIT_FUNC_ARGS_PASSTHRU);
  update_ca_bundle_local_path(INIT_FUNC_ARGS_PASSTHRU);
  if (FLAGS_php_allow_file_redirect) {
    load_redirect_paths(INIT_FUNC_ARGS_PASSTHRU);
  }


  // Register our php://input handler.
  php_unregister_url_stream_wrapper(const_cast<char *>("php") TSRMLS_CC);
  php_register_url_stream_wrapper(const_cast<char *>("php"),
                                  &php_input_stream_wrapper TSRMLS_CC);

  // Register our __redirect:// stream handler
  php_register_url_stream_wrapper(
      const_cast<char*>(kRedirectProtocol),
      &php_redirect_stream_wrapper TSRMLS_CC);

  if (FLAGS_php_enforce_filesystem_readonly &&
      !GAERT_G(disable_readonly_filesystem)) {
    appengine::hook_readonly_filesystem_wrapper(
        &php_plain_files_wrapper TSRMLS_CC);
  }

  zend_module_entry* modules_to_register[] = {
    &fake_memcache_module_entry,
    &fake_memcached_module_entry,
    &urlfetch_stream_wrapper_module_entry,
    // Must be NULL terminated.
    NULL,
  };

  // Can't use zend_next_free_module() directly here as it is not declared
  // as ZEND_API, and thus unavailable when building on Windows.
  int next_free_module = zend_hash_num_elements(&module_registry) + 1;
  for (int i=0; modules_to_register[i] != NULL; ++i) {
    modules_to_register[i]->module_number = next_free_module++;
    zend_register_module_ex(modules_to_register[i] TSRMLS_CC);
  }

  if (GAERT_G(enable_curl_lite)) {
    fake_curl_module_entry.module_number = next_free_module++;
    zend_register_module_ex(&fake_curl_module_entry TSRMLS_CC);
  }

  return SUCCESS;
}

// Module shutdown function
static PHP_MSHUTDOWN_FUNCTION(gae_runtime_module) {
  php_unregister_url_stream_wrapper(const_cast<char *>("php") TSRMLS_CC);

  release_static_resources(TSRMLS_C);

#ifdef ZTS
  ts_free_id(gae_runtime_module_globals_id);
#endif

  UNREGISTER_INI_ENTRIES();
  return SUCCESS;
}

// Request initialization function
static PHP_RINIT_FUNCTION(gae_runtime_module) {
  if (user_ini_hash_table) {
    // php_ini_activate_config is not thread safe.
    MutexLock l(&request_init_mutex);
    php_ini_activate_config(user_ini_hash_table,
                            PHP_INI_PERDIR,
                            PHP_INI_STAGE_HTACCESS TSRMLS_CC);
  }

  return SUCCESS;
}

// Request shutdown function
static PHP_RSHUTDOWN_FUNCTION(gae_runtime_module) {
  // For now, nothing to initialize.
  return SUCCESS;
}

// Module info function.
static PHP_MINFO_FUNCTION(gae_runtime_module) {
  php_info_print_table_start();
  php_info_print_table_header(2, "Google App Engine Runtime Module", "enabled");
  php_info_print_table_end();

  DISPLAY_INI_ENTRIES();
}

// Make an API call to the appserver, using the callback that is supplied in
// the SAPI request context.
//
// Arguments:
//  - package: string name of the package for the API call.
//  - call: string name of the call to make
//  - request: string request protobuf
//  - result_array: A PHP array type for storage of the results of the API call
//    to be returned to the called.
//  - callback: callback for when the call is completed.
//  - deadline: number of seconds to allow for the RPC
//
// Throws:
// - InvalidArgumentException: If the supplied callback is not callable.
PHP_FUNCTION(make_call) {
  char* package = NULL;
  int package_len = 0;
  char* call_name = NULL;
  int call_name_len = 0;
  char* request = NULL;
  int request_len = 0;
  zval* result_array = NULL;
  zval* callback = NULL;
  long deadline = -1;  // NOLINT

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                            const_cast<char*>("sssa|z!l"),
                            &package, &package_len,
                            &call_name, &call_name_len,
                            &request, &request_len,
                            &result_array,
                            &callback,
                            &deadline) == FAILURE) {
    // TODO(slangley): Throw exception?
    php_error(E_WARNING, "Unable to parse parameters.");
    return;
  }

  char* callback_name = NULL;
  if (callback != NULL &&
      !zend_is_callable(callback, 0, &callback_name TSRMLS_CC)) {
    zend_throw_exception_ex(spl_ce_InvalidArgumentException,
                            0 TSRMLS_CC,
                            const_cast<char*>("%s is not a valid callback."),
                            callback_name);
    if (callback_name) {
      efree(callback_name);
    }
    return;
  }

  if (callback_name) {
    efree(callback_name);
  }

  // TODO(slangley): Async requests from user PHP is not possible, due to the
  // single threading memory model. For now, this request must always be sync.
  string package_str(package, package_len);
  string call_str(call_name, call_name_len);
  string request_str(request, request_len);
  PhpApiRpc rpc;

  PhpRpcUtils::MakeApiCall(&rpc,
                           package_str,
                           call_str,
                           request_str,
                           deadline TSRMLS_CC);

  add_assoc_long(result_array, appengine::kErrorCodeName, rpc.error());
  add_assoc_long(result_array,
                 appengine::kApplicationErrorCodeName,
                 rpc.app_error());
  add_assoc_string(result_array,
                   appengine::kApplicationErrorDetailName,
                   const_cast<char*>(rpc.error_detail().c_str()),
                   1);
  add_assoc_stringl(result_array,
                    appengine::kResultStringName,
                    const_cast<char*>(rpc.response_pb().c_str()),
                    rpc.response_pb().length(),
                    1);
  add_assoc_long(result_array, appengine::kCpuUsageName, rpc.cpu_usage());


  zval dummy_retval;

  if (callback != NULL) {
    call_user_function(EG(function_table),
                       NULL,
                       callback,
                       &dummy_retval,
                       0,
                       NULL TSRMLS_CC);
  }

  RETURN_NULL();
}

// Type of zend_error_cb, which does not have a public definition
static void (*old_error_handler)(int,
                                 const char*,
                                 const uint,
                                 const char*,
                                 va_list);

// Error handler installed during the lint_string function - this captures
// errors into an array without reporting them or altering that state of the
// interpreter.
static void lint_error_handler(int error_num,
                               const char* filename,
                               uint line_no,
                               const char* format,
                               va_list args) {
  TSRMLS_FETCH();

  zval* error_array;
  MAKE_STD_ZVAL(error_array);
  array_init(error_array);
  add_assoc_long(error_array, "error_number", error_num);
  add_assoc_string(error_array, "file_name", const_cast<char*>(filename), 1);
  add_assoc_long(error_array, "line_number", line_no);

  char* buffer;
  int buffer_len = vspprintf(&buffer, PG(log_errors_max_len), format, args);
  add_assoc_stringl(error_array, "error_message", buffer, buffer_len, 0);

  add_next_index_zval(GAERT_G(recorded_errors_array), error_array);
}

// lint a string containing PHP code.
// Based on the php_lint_script function.
//
// Arguments:
// string - the script code.
// string - the name of the file being linted
//
// Returns:
// An array of associative arrays of linter errors from parsing the string.
PHP_FUNCTION(lint_string) {
  char* script_code = NULL;
  int script_code_len = 0;
  char* filename = NULL;
  int filename_len = 0;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                            const_cast<char*>("ss"),
                            &script_code, &script_code_len,
                            &filename, &filename_len) == FAILURE) {
    php_error(E_WARNING, "Unable to parse parameters.");
    RETURN_FALSE;
  }

  // If the user is not using the return value then do nothing.
  if (!return_value_used) {
    php_error_docref(NULL TSRMLS_CC, E_NOTICE,
                     "lint_string called without processing output");
    RETURN_NULL();
  }

  // Initialize the return_value and then share the pointer with the module
  // global state. We will write the error messages directly into the
  // return_value.
  array_init(return_value);
  GAERT_G(recorded_errors_array) = return_value;

  int retval = FAILURE;
  zend_op_array* op_array;
  // Replace the error callback with our own handler, that just records the
  // errors but does not modify the executor state.
  old_error_handler = zend_error_cb;
  zend_error_cb = lint_error_handler;

  zend_try {
    zval pv;
    Z_STRLEN(pv) = script_code_len;
    Z_STRVAL(pv) = script_code;
    Z_TYPE(pv) = IS_STRING;

    op_array = zend_compile_string(&pv, filename TSRMLS_CC);

    if (op_array) {
      destroy_op_array(op_array TSRMLS_CC);
      efree(op_array);
    }
    retval = SUCCESS;
  } zend_end_try();

  // Reinstall saved state.
  zend_error_cb = old_error_handler;
  GAERT_G(recorded_errors_array) = NULL;

  // If successful, we will return the array - otherwise we will return FALSE.
  if (retval == FAILURE) {
    zval_dtor(return_value);
    RETURN_FALSE;
  }
}

// Implement tmpfile() using an in-memory stream. Note that the type returned
// here is <php_stream *> rather than <FILE *> but that should be transparent
// to most applications.
PHP_FUNCTION(memory_tmpfile) {
  if (zend_parse_parameters_none() == FAILURE) {
    return;
  }
  php_stream_to_zval(php_stream_memory_create(TEMP_STREAM_DEFAULT),
                     return_value);
}

// Return an associative array of the user defined stream redirect paths.
PHP_FUNCTION(get_stream_redirect_paths) {
  array_init(return_value);

  MutexLock l(&redirect_path_ht_mutex);
  HashPosition pos;

  for (zend_hash_internal_pointer_reset_ex(redirect_path_hash_table, &pos);
      zend_hash_has_more_elements_ex(redirect_path_hash_table, &pos) == SUCCESS;
      zend_hash_move_forward_ex(redirect_path_hash_table, &pos)) {
    char* key;
    uint keylen;
    ulong idx;

    if (zend_hash_get_current_key_ex(redirect_path_hash_table,
                                     &key,
                                     &keylen,
                                     &idx,
                                     0,
                                     &pos) == HASH_KEY_IS_STRING) {
      char** data;
      if (zend_hash_get_current_data_ex(redirect_path_hash_table,
                                        reinterpret_cast<void**>(&data),
                                        &pos) == SUCCESS) {
        add_assoc_string(return_value, key, *data, 1);
      }
    }
  }
}

// Add cross stream wrapper type support to rename() using copy-then-unlink.
// The remainder part of the function is copied directly from PHP's default
// implementation.
//
// Arguments:
// string - The old file name
// string - The new file name
// context - Optional stream context
//
// Returns:
// TRUE on success or FALSE on failure.
PHP_FUNCTION(cross_stream_wrapper_rename) {
  char *old_name, *new_name;
  int old_name_len, new_name_len;
  zval *zcontext = NULL;
  php_stream_wrapper *wrapper = NULL;
  php_stream_context *context = NULL;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                            "pp|r",
                            &old_name,
                            &old_name_len,
                            &new_name,
                            &new_name_len,
                            &zcontext) == FAILURE) {
    RETURN_FALSE;
  }

  // Determine redirect paths now so we can retrieve the correct stream wrappers
  char* old_name_redirect = NULL;
  if (appengine::is_redirect_path(old_name, &old_name_redirect TSRMLS_CC)) {
    old_name = old_name_redirect;
  }
  char* new_name_redirect = NULL;
  if (appengine::is_redirect_path(new_name, &new_name_redirect TSRMLS_CC)) {
    new_name = new_name_redirect;
  }

  wrapper = appengine::get_correct_stream_wrapper(old_name,
                                                  &old_name,
                                                  0 TSRMLS_CC);

  if (!wrapper || !wrapper->wops) {
    php_error_docref(
        NULL TSRMLS_CC, E_WARNING, "Unable to locate stream wrapper");
    RETURN_FALSE;
  }

  if (!wrapper->wops->rename) {
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                     "%s wrapper does not support renaming",
                     wrapper->wops->label ? wrapper->wops->label : "Source");
    RETURN_FALSE;
  }

  // This is the only part changed from the original implementation. Instead of
  // giving up and printing an error message, use copy-then-unlink to rename
  // across different types of wrapper.
  if (wrapper != appengine::get_correct_stream_wrapper(new_name,
                                                       &new_name,
                                                       0 TSRMLS_CC) &&
      wrapper->wops->unlink) {
    if (php_copy_file_ctx(old_name,
                          new_name,
                          0,
                          context TSRMLS_CC) != SUCCESS) {
      RETURN_FALSE;
    }

    RETURN_BOOL(wrapper->wops->unlink(
        wrapper, old_name, REPORT_ERRORS, context TSRMLS_CC));
  }

  context = reinterpret_cast<php_stream_context*>(
      php_stream_context_from_zval(zcontext, 0));

  RETURN_BOOL(wrapper->wops->rename(
      wrapper, old_name, new_name, 0, context TSRMLS_CC));
}

// Provide undocumented function for removing a file from rfc1867_uploaded_files
// hash for use by the user-space implementation of move_uploaded_file().
PHP_FUNCTION(__remove_uploaded_file) {
  if (!SG(rfc1867_uploaded_files)) {
    RETURN_FALSE;
  }

  char* name = NULL;
  int name_len = 0;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                            "s",
                            &name, &name_len) == FAILURE) {
    RETURN_FALSE;
  }

  if (!zend_hash_exists(SG(rfc1867_uploaded_files),
                        name,
                        name_len + 1)) {
    php_error(E_WARNING, "Not an uploaded file.");
    RETURN_FALSE;
  }

  zend_hash_del(SG(rfc1867_uploaded_files), name, name_len + 1);
  RETURN_TRUE;
}

PHP_FUNCTION(glob) {
  char* pattern = NULL;
  int pattern_len;
  long flags = 0;
  zval* z_function_name;
  zval* z_args[2];
  zval* z_pattern;
  zval* z_flags;
  zval* z_retval = NULL;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                            "p|l",
                            &pattern,
                            &pattern_len,
                            &flags) == FAILURE) {
    return;
  }
  if (pattern_len >= MAXPATHLEN) {
    php_error_docref(
        NULL TSRMLS_CC,
        E_WARNING,
        "Pattern exceeds the maximum allowed length of %d characters",
        MAXPATHLEN);
    RETURN_FALSE;
  }

  MAKE_STD_ZVAL(z_function_name);
  MAKE_STD_ZVAL(z_pattern);
  MAKE_STD_ZVAL(z_flags);
  MAKE_STD_ZVAL(z_retval);

  ZVAL_STRING(z_function_name, kGlobFunctionName, 1);
  ZVAL_STRINGL(z_pattern, pattern, pattern_len, 1);
  ZVAL_LONG(z_flags, flags);


  z_args[0] = z_pattern;
  z_args[1] = z_flags;

  if (call_user_function(EG(function_table),
                         NULL,
                         z_function_name,
                         z_retval,
                         2,
                         z_args TSRMLS_CC) == SUCCESS) {
    if (z_retval) {
      COPY_PZVAL_TO_ZVAL(*return_value, z_retval);
    }
  } else {
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                     "Unable to call %s()", kGlobFunctionName);
  }

  zval_ptr_dtor(&z_function_name);
  zval_ptr_dtor(&z_pattern);
  zval_ptr_dtor(&z_flags);
}

// A wrapper for user-space implementation of tempnam().
PHP_FUNCTION(userspace_tempnam) {
  char *dir, *prefix;
  int dir_len, prefix_len;
  zval* z_function_name;
  zval* z_args[2];
  zval* z_dir;
  zval* z_prefix;
  zval* z_retval = NULL;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                            "ps",
                            &dir,
                            &dir_len,
                            &prefix,
                            &prefix_len) == FAILURE) {
    return;
  }

  MAKE_STD_ZVAL(z_function_name);
  MAKE_STD_ZVAL(z_dir);
  MAKE_STD_ZVAL(z_prefix);
  MAKE_STD_ZVAL(z_retval);

  ZVAL_STRING(z_function_name, kTempnamFunctionName, 1);
  ZVAL_STRINGL(z_dir, dir, dir_len, 1);
  ZVAL_STRINGL(z_prefix, prefix, prefix_len, 1);

  z_args[0] = z_dir;
  z_args[1] = z_prefix;

  if (call_user_function(EG(function_table),
                         NULL,
                         z_function_name,
                         z_retval,
                         2,
                         z_args TSRMLS_CC) == SUCCESS) {
    if (z_retval) {
      COPY_PZVAL_TO_ZVAL(*return_value, z_retval);
    }
  } else {
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                     "Unable to call %s()", kTempnamFunctionName);
  }

  zval_ptr_dtor(&z_function_name);
  zval_ptr_dtor(&z_dir);
  zval_ptr_dtor(&z_prefix);
}

// A wrapper for user-space implementation of sys_get_temp_dir().
PHP_FUNCTION(userspace_sys_get_temp_dir) {
  zval* z_function_name;
  zval* z_retval = NULL;

  if (zend_parse_parameters_none() == FAILURE) {
    return;
  }

  MAKE_STD_ZVAL(z_function_name);
  MAKE_STD_ZVAL(z_retval);

  ZVAL_STRING(z_function_name, kSysGetTempDirFunctionName, 1);

  if (call_user_function(EG(function_table),
                         NULL,
                         z_function_name,
                         z_retval,
                         0,
                         NULL TSRMLS_CC) == SUCCESS) {
    if (z_retval) {
      COPY_PZVAL_TO_ZVAL(*return_value, z_retval);
    }
  } else {
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                     "Unable to call %s()", kSysGetTempDirFunctionName);
  }

  zval_ptr_dtor(&z_function_name);
}

// A wrapper for user-space implementation of mail().
PHP_FUNCTION(userspace_mail) {
  char *to = NULL;
  char *subject = NULL;
  char *message = NULL;
  char *headers = NULL;
  char *extra_cmd = NULL;
  int to_len = 0;
  int subject_len = 0;
  int message_len = 0;
  int headers_len = 0;
  int extra_cmd_len = 0;
  zval* z_function_name;
  zval* z_retval = NULL;
  zval* z_args[5];

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                            "sss|ss",
                            &to,
                            &to_len,
                            &subject,
                            &subject_len,
                            &message,
                            &message_len,
                            &headers,
                            &headers_len,
                            &extra_cmd,
                            &extra_cmd_len) == FAILURE) {
    return;
  }

  if (!GAERT_G(enable_mail_replacement)) {
    zend_error(E_WARNING, "The function 'mail' is not implemented.");
    RETURN_FALSE;
  }

  MAKE_STD_ZVAL(z_function_name);
  MAKE_STD_ZVAL(z_retval);
  for (int i = 0; i < 5; i++) {
    MAKE_STD_ZVAL(z_args[i]);
  }

  ZVAL_STRINGL(z_args[0], to, to_len, 1);
  ZVAL_STRINGL(z_args[1], subject, subject_len, 1);
  ZVAL_STRINGL(z_args[2], message, message_len, 1);

  if (headers) {
    ZVAL_STRINGL(z_args[3], headers, headers_len, 1);
  } else {
    ZVAL_NULL(z_args[3]);
  }

  if (extra_cmd) {
    ZVAL_STRINGL(z_args[4], extra_cmd, extra_cmd_len, 1);
  } else {
    ZVAL_NULL(z_args[4]);
  }

  ZVAL_STRING(z_function_name, kMailFunctionName, 1);

  if (call_user_function(EG(function_table),
                         NULL,
                         z_function_name,
                         z_retval,
                         5,
                         z_args TSRMLS_CC) == SUCCESS) {
    if (z_retval) {
      COPY_PZVAL_TO_ZVAL(*return_value, z_retval);
    }
  } else {
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                     "Unable to call %s()", kMailFunctionName);
  }

  zval_ptr_dtor(&z_function_name);
  for (int i = 0; i < 5; i++) {
    zval_ptr_dtor(&z_args[i]);
  }
}

PHP_FUNCTION(gcs_clearstatcache) {
  zend_bool  clear_realpath_cache = 0;
  char      *filename             = NULL;
  int        filename_len         = 0;

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                            "|bp",
                            &clear_realpath_cache,
                            &filename,
                            &filename_len) == FAILURE) {
    return;
  }

  zval* z_function_name;
  zval* z_retval;
  zval* z_args[1];
  MAKE_STD_ZVAL(z_function_name);
  MAKE_STD_ZVAL(z_args[0]);
  MAKE_STD_ZVAL(z_retval);

  ZVAL_STRING(z_function_name, kClearGcsStatCacheFunctionName, 1);
  ZVAL_STRINGL(z_args[0], filename, filename_len, 0);

  int arg_count = filename != NULL ? 1 : 0;

  if (call_user_function(EG(function_table),
                         NULL,
                         z_function_name,
                         z_retval,
                         arg_count,
                         z_args TSRMLS_CC) != SUCCESS) {
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                     "Unable to call %s()", kClearGcsStatCacheFunctionName);
  }
  FREE_ZVAL(z_args[0]);
  FREE_ZVAL(z_function_name);
  FREE_ZVAL(z_retval);

  php_clear_stat_cache(clear_realpath_cache, filename, filename_len TSRMLS_CC);
}

// A wrapper for user-space implementation of gethostname().
PHP_FUNCTION(userspace_gethostname) {
  zval* z_function_name;
  zval* z_retval;

  if (zend_parse_parameters_none() == FAILURE) {
    return;
  }

  MAKE_STD_ZVAL(z_function_name);
  MAKE_STD_ZVAL(z_retval);

  ZVAL_STRING(z_function_name, kGetHostnameFunctionName, 1);

  if (call_user_function(EG(function_table),
                         NULL,
                         z_function_name,
                         z_retval,
                         0,
                         NULL TSRMLS_CC) != SUCCESS) {
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                     "Unable to call %s()", kGetHostnameFunctionName);
  } else {
      COPY_PZVAL_TO_ZVAL(*return_value, z_retval);
  }

  zval_ptr_dtor(&z_function_name);
}

// A wrapper for user-space implementation of move_uploaded_file().
PHP_FUNCTION(userspace_move_uploaded_file) {
  char *filename = NULL;
  char *destination = NULL;
  int filename_len = 0;
  int destination_len = 0;
  zval *context_options = NULL;
  zval *z_function_name;
  zval *z_retval = NULL;
  zval *z_args[3];

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                            "ss|a",
                            &filename,
                            &filename_len,
                            &destination,
                            &destination_len,
                            &context_options) == FAILURE) {
    return;
  }

  MAKE_STD_ZVAL(z_function_name);
  MAKE_STD_ZVAL(z_retval);
  for (int i = 0; i < 3; i++) {
    MAKE_STD_ZVAL(z_args[i]);
  }

  ZVAL_STRING(z_function_name, kMoveUploadedFileFunctionName, 1);
  ZVAL_STRINGL(z_args[0], filename, filename_len, 1);
  ZVAL_STRINGL(z_args[1], destination, destination_len, 1);
  if (context_options) {
    ZVAL_ZVAL(z_args[2], context_options, 1, 1);
  } else {
    ZVAL_NULL(z_args[2]);
  }

  if (call_user_function(EG(function_table),
                         NULL,
                         z_function_name,
                         z_retval,
                         3,
                         z_args TSRMLS_CC) == SUCCESS) {
    if (z_retval) {
      COPY_PZVAL_TO_ZVAL(*return_value, z_retval);
    }
  } else {
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                     "Unable to call %s()", kMoveUploadedFileFunctionName);
  }

  zval_ptr_dtor(&z_function_name);
  for (int i = 0; i < 3; i++) {
    zval_ptr_dtor(&z_args[i]);
  }
}

// A wrapper for user-space implementation of syslog().
PHP_FUNCTION(userspace_syslog) {
  long priority;
  char *message;
  int message_len;
  zval *z_function_name;
  zval *z_retval = NULL;
  zval *z_args[2];

  if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                            "ls",
                            &priority,
                            &message,
                            &message_len) == FAILURE) {
    return;
  }

  MAKE_STD_ZVAL(z_function_name);
  MAKE_STD_ZVAL(z_args[0]);
  MAKE_STD_ZVAL(z_args[1]);
  MAKE_STD_ZVAL(z_retval);

  ZVAL_STRING(z_function_name, kLogFunctionName, 1);
  ZVAL_LONG(z_args[0], kSyslogPriorityMap[priority & kSyslogPriorityMask]);
  ZVAL_STRINGL(z_args[1], message, message_len, 1);

  if (call_user_function(EG(function_table),
                         NULL,
                         z_function_name,
                         z_retval,
                         2,
                         z_args TSRMLS_CC) != SUCCESS) {
    php_error_docref(NULL TSRMLS_CC, E_WARNING,
                     "Unable to call %s()", kLogFunctionName);

    if (z_retval) {
      COPY_PZVAL_TO_ZVAL(*return_value, z_retval);
    }
  }

  zval_ptr_dtor(&z_function_name);
  zval_ptr_dtor(&z_args[0]);
  zval_ptr_dtor(&z_args[1]);
}

// Arguments for make_call
ZEND_BEGIN_ARG_INFO_EX(make_call_arginfo, 0, 0, 4)
  ZEND_ARG_INFO(0, pacakge)
  ZEND_ARG_INFO(0, call)
  ZEND_ARG_INFO(0, request_data)
  ZEND_ARG_ARRAY_INFO(1, result_array, 0)
  ZEND_ARG_INFO(0, callback)  // Optional
  ZEND_ARG_INFO(0, deadline)  // Optional
ZEND_END_ARG_INFO()

// Arguments for lint_string
ZEND_BEGIN_ARG_INFO_EX(lint_string_arginfo, 0, 0, 2)
  ZEND_ARG_INFO(0, script_code)
  ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(memory_tmpfile_arginfo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(get_stream_redirect_paths_arginfo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(cross_stream_wrapper_rename_arginfo, 0, 0, 2)
  ZEND_ARG_INFO(0, old_name)
  ZEND_ARG_INFO(0, new_name)
  ZEND_ARG_INFO(0, context)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(__remove_uploaded_file_arginfo, 0, 0, 1)
  ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(glob_arginfo, 0, 0, 1)
  ZEND_ARG_INFO(0, pattern)
  ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(userspace_tempnam_arginfo, 0, 0, 2)
  ZEND_ARG_INFO(0, dir)
  ZEND_ARG_INFO(0, prefix)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(userspace_sys_get_temp_dir_arginfo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(userspace_mail_arginfo, 0, 0, 3)
  ZEND_ARG_INFO(0, to)
  ZEND_ARG_INFO(0, subject)
  ZEND_ARG_INFO(0, message)
  ZEND_ARG_INFO(0, headers)  // Optional
  ZEND_ARG_INFO(0, etra_cmd)  // Optional
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(userspace_syslog_arginfo, 0, 0, 2)
  ZEND_ARG_INFO(0, priority)
  ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(gcs_clearstatcache_arginfo, 0, 0, 0)
  ZEND_ARG_INFO(0, clear_realpath_cache)
  ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(userspace_gethostname_arginfo, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(userspace_move_uploaded_file_arginfo, 0, 0, 2)
  ZEND_ARG_INFO(0, filename)
  ZEND_ARG_INFO(0, destination)
  ZEND_ARG_INFO(0, context_options)  // Optional
ZEND_END_ARG_INFO()

// Define user visible functions
static const zend_function_entry gae_runtime_module_functions[] = {
  PHP_FE(make_call, make_call_arginfo)
  PHP_FE(lint_string, lint_string_arginfo)
  PHP_FE(get_stream_redirect_paths, get_stream_redirect_paths_arginfo)
  PHP_FE(__remove_uploaded_file, __remove_uploaded_file_arginfo)
  PHP_FE_END
};

// Define built in functions we replace at startup
static const zend_function_entry runtime_builtin_replacement_functions[] = {
  // TODO(marslan): Remove tmpfile replacement once PHP 5.4 is fully turned
  //  down, as the fix for b/22120224 is only applied to PHP 5.5 interpreter.
  PHP_NAMED_FE(tmpfile, PHP_FN(memory_tmpfile), memory_tmpfile_arginfo)
  PHP_NAMED_FE(mail, PHP_FN(userspace_mail), userspace_mail_arginfo)
  PHP_NAMED_FE(gethostname,
               PHP_FN(userspace_gethostname),
               userspace_gethostname_arginfo)
  PHP_NAMED_FE(move_uploaded_file,
               PHP_FN(userspace_move_uploaded_file),
               userspace_move_uploaded_file_arginfo)
  PHP_FE_END
};

// Define replacement functions for cross stream wrapper type renaming
static const zend_function_entry rename_replacement_functions[] = {
  PHP_NAMED_FE(rename,
               PHP_FN(cross_stream_wrapper_rename),
               cross_stream_wrapper_rename_arginfo)
  PHP_FE_END
};

static const zend_function_entry glob_replacement_functions[] = {
  PHP_NAMED_FE(glob, PHP_FN(glob), glob_arginfo)
  PHP_FE_END
};

static const zend_function_entry tempnam_replacement_functions[] = {
  PHP_NAMED_FE(tempnam, PHP_FN(userspace_tempnam), userspace_tempnam_arginfo)
  PHP_NAMED_FE(sys_get_temp_dir,
               PHP_FN(userspace_sys_get_temp_dir),
               userspace_sys_get_temp_dir_arginfo)
  PHP_FE_END
};

static const zend_function_entry clearstatcache_replacement_functions[] = {
  PHP_NAMED_FE(clearstatcache,
               PHP_FN(gcs_clearstatcache),
               gcs_clearstatcache_arginfo)
  PHP_FE_END
};

static const zend_function_entry syslog_replacement_functions[] = {
  PHP_NAMED_FE(syslog, PHP_FN(userspace_syslog), userspace_syslog_arginfo)
  PHP_FE_END
};

static void zend_replace_functions(
    const zend_function_entry* functions TSRMLS_DC) {
  const zend_function_entry* fe_ptr = functions;
  while (fe_ptr->fname) {
    // Remove the old entry
    zend_hash_del(CG(function_table), fe_ptr->fname, strlen(fe_ptr->fname) + 1);
    ++fe_ptr;
  }

  zend_register_functions(NULL,
                          functions,
                          CG(function_table),
                          MODULE_PERSISTENT TSRMLS_CC);
}

static void replace_builtin_functions(INIT_FUNC_ARGS) {
  zend_replace_functions(runtime_builtin_replacement_functions TSRMLS_CC);

  if (FLAGS_php_enable_cross_stream_wrapper_rename) {
    zend_replace_functions(rename_replacement_functions TSRMLS_CC);
  }

  if (FLAGS_php_enable_glob_replacement) {
    zend_replace_functions(glob_replacement_functions TSRMLS_CC);
  }

  if (FLAGS_php_enable_tempnam) {
    zend_replace_functions(tempnam_replacement_functions TSRMLS_CC);
  }

  if (FLAGS_php_enable_gcs_stat_cache) {
    zend_replace_functions(clearstatcache_replacement_functions TSRMLS_CC);
  }

  if (FLAGS_php_enable_syslog_replacement) {
    zend_replace_functions(syslog_replacement_functions TSRMLS_CC);
  }
}

// Module dependancies are used to ensure that the runtime module is initialized
// last, so that we can strip out functions, streams and transports
static const zend_module_dep gae_runtime_module_dep[] = {
  ZEND_MOD_OPTIONAL("standard")
  ZEND_MOD_OPTIONAL("session")
  ZEND_MOD_OPTIONAL("openssl")
  ZEND_MOD_OPTIONAL("curl")
  ZEND_MOD_END
};

zend_module_entry gae_runtime_module_entry = {
  STANDARD_MODULE_HEADER_EX,
  NULL,
  gae_runtime_module_dep,
  const_cast<char*>("GAE Runtime Module"),
  gae_runtime_module_functions,
  PHP_MINIT(gae_runtime_module),
  PHP_MSHUTDOWN(gae_runtime_module),
  PHP_RINIT(gae_runtime_module),
  PHP_RSHUTDOWN(gae_runtime_module),
  PHP_MINFO(gae_runtime_module),
  NO_VERSION_YET,
  PHP_MODULE_GLOBALS(gae_runtime_module),
  NULL,
  NULL,
  NULL,
  STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_GAE_RUNTIME_MODULE
ZEND_GET_MODULE(gae_runtime)
#endif

zend_module_entry fake_memcache_module_entry = {
  STANDARD_MODULE_HEADER_EX,
  NULL,
  NULL,  // dependancies
  const_cast<char*>("memcache"),
  NULL,  // functions
  NULL,  // MINIT
  NULL,  // MSHUTDOWN
  NULL,  // RINIT
  NULL,  // RSHUTDOWN
  NULL,  // MINFO
  NO_VERSION_YET,
  STANDARD_MODULE_PROPERTIES
};

zend_module_entry fake_memcached_module_entry = {
  STANDARD_MODULE_HEADER_EX,
  NULL,
  NULL,  // dependancies
  const_cast<char*>("memcached"),
  NULL,  // functions
  NULL,  // MINIT
  NULL,  // MSHUTDOWN
  NULL,  // RINIT
  NULL,  // RSHUTDOWN
  NULL,  // MINFO
  NO_VERSION_YET,
  STANDARD_MODULE_PROPERTIES
};

zend_module_entry fake_curl_module_entry = {
  STANDARD_MODULE_HEADER_EX,
  NULL,
  NULL,  // dependancies
  const_cast<char*>("curl"),
  NULL,  // functions
  NULL,  // MINIT
  NULL,  // MSHUTDOWN
  NULL,  // RINIT
  NULL,  // RSHUTDOWN
  NULL,  // MINFO
  NO_VERSION_YET,
  STANDARD_MODULE_PROPERTIES
};
