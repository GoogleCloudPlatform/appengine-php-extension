dnl Copyright 2016 Google Inc. All Rights Reserved.
dnl
dnl Licensed under the Apache License, Version 2.0 (the "License");
dnl you may not use this file except in compliance with the License.
dnl You may obtain a copy of the License at
dnl
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS-IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.
dnl

PHP_ARG_ENABLE(gae, weather to enable Google App Engine support,
[  --enable-gae            Enable Google App Engine support.)])

PHP_ARG_WITH(protobuf_inc, for protobuf headers,
[  --with-protobuf_inc[=DIR]       Define the location of the protobuf headers.)])

PHP_ARG_WITH(protobuf_lib, for protobuf libraries,
[  --with-protobuf_lib[=DIR]       Define the location of the protobuf libraries.)])

if test "$PHP_GAE" != "no"; then
  PHP_REQUIRE_CXX()

  gae_src="gae_runtime_module.cc
    gae_runtime_module_stub.cc
    php_features_stub.cc
    php_stream_wrapper.cc
    php_readonly_filesystem_wrapper.cc
    php_redirect_filesystem_wrapper.cc
    php_rpc_utils_stub.cc
    php_runtime_utils_stub.cc
    php_runtime_sapi_stub.cc
    remote_api.pb.cc
    urlfetch_service.pb.cc
    urlfetch_stream_wrapper.cc"

  if test -r "$PHP_PROTOBUF_INC/google/protobuf/message.h"; then
    protobuf_inc=$PHP_PROTOBUF_INC
  else
    AC_MSG_ERROR([Invalid protobuf include path $PHP_PROTOBUF_INC])
  fi

  if test -d "$PHP_PROTOBUF_LIB"; then
    protobuf_lib=$PHP_PROTOBUF_LIB
  else
    AC_MSG_ERROR([Invalid protobuf library path $PHP_PROTOBUF_LIB])
  fi

  FLAGS="-DUSE_REMOTE_API -fPIC -I$protobuf_inc"

  dnl Assume libprotobuf.dylib is built using libc++.
  if [[[ "$host_alias" == *darwin* ]]]; then
    FLAGS="$FLAGS -stdlib=libc++"
  fi

  PHP_NEW_EXTENSION(gae_runtime_module, $gae_src, $ext_shared, , $FLAGS)

  GAE_RUNTIME_MODULE_SHARED_LIBADD="-L$protobuf_lib -lprotobuf"
  PHP_SUBST(GAE_RUNTIME_MODULE_SHARED_LIBADD)
fi
