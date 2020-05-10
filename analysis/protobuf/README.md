# Description

1. Extract the proto files from the library using [pbtk](https://github.com/marin-m/pbtk) and save them under the directory `./protos`
2. Extract the messages using the following `protoc` command:  
```$ protoc --python_out=./proto_python --proto_path=. $(find ./protos -iname "*.proto")```
3. Decode the `dictation.config` file with the following command:  
```$ python decode_and_export_config.py dictation.config dictation.decoded.config```