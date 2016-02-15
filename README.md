# [Google App Engine](https://cloud.google.com/appengine/) PHP Runtime Extension

This repository contains the GAE PHP runtime extension, which enables emulation of the App Engine environment for local development.

## Building

1. Install [Protocol Buffer complier](https://developers.google.com/protocol-buffers/) for your platform.

1. Generate C++ source and header files for [remote_api.proto](remote_api.proto) and [urlfetch_service.proto](urlfetch_service.proto).

        protoc --cpp_out=. remote_api.proto
        protoc --cpp_out=. urlfetch_service.proto

1. Familiarize yourself with the [PHP extension building](http://www.phpinternalsbook.com/build_system/building_extensions.html#building-extensions-using-phpize) process, and run the following commands. Set ``<include_path>`` and ``<lib_path>`` to where you have installed the protobuf headers and libraries in the previous step.

        phpize
        ./configure --enable-gae --with-protobuf_inc=<include_path> --with-protobuf_lib=<lib_path>
        make

1. The compiled extension can be found in ``modules/gae_runtime_module.so``. Use the ``--php_gae_extension_path`` flag to load the extension when running the [development server](https://cloud.google.com/appengine/docs/php/tools/devserver).

## Contributing
Have a patch that will benefit this project? Awesome! Follow these steps to have it accepted.

1. Please sign our [Contributor License Agreement](CONTRIBUTING.md).
1. Fork this Git repository and make your changes.
1. Create a Pull Request
1. Incorporate review feedback to your changes.
1. Accepted!

## License
All files in this repository are under the [Apache v2](LICENSE) unless noted otherwise.
