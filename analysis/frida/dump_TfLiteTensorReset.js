'use strict';

// Types supported by tensor
const TfLiteType = {
  kTfLiteNoType: 0,
  kTfLiteFloat32: 1,
  kTfLiteInt32: 2,
  kTfLiteUInt8: 3,
  kTfLiteInt64: 4,
  kTfLiteString: 5,
  kTfLiteBool: 6,
  kTfLiteInt16: 7,
  kTfLiteComplex64: 8,
  kTfLiteInt8: 9,
  kTfLiteFloat16: 10,
  kTfLiteFloat64: 11,
};

const TfLiteTypeSize = {
  kTfLiteNoType: 0,
  kTfLiteFloat32: 4,
  kTfLiteInt32: 4,
  kTfLiteUInt8: 1,
  kTfLiteInt64: 8,
  kTfLiteString: 8,
  kTfLiteBool: 1,
  kTfLiteInt16: 2,
//   kTfLiteComplex64: 8,
  kTfLiteInt8: 1,
  kTfLiteFloat16: 2,
  kTfLiteFloat64: 8,
}

const TfLiteAllocationType = {
  kTfLiteMemNone: 0,
  kTfLiteMmapRo: 1,
  kTfLiteArenaRw: 2,
  kTfLiteArenaRwPersistent: 3,
  kTfLiteDynamic: 4,
};

function TfLiteIntArray(address) {
    this._pointer = address
    this.size = this._pointer.readU32();

    // Get Shapes
    this.data = []
    for (var i = 1; i <= this.size; i++) {
        var v = this._pointer.add(4*i).readU32();
        this.data.push(v);
    }
}

function _TfDataArray(address, type, size) {
    console.log(address, type, size)
    console.log(address.readByteArray(128))

    this.size = size
}

function TfLiteTensorReset(args) {
    this.type = Object.keys(TfLiteType)[parseInt(args[0])];
    this.name = args[1].readCString();
    this._dims_p = args[2];
    this.dims =  args[2].readU32();
    this.quantization = args[3]
    this.buffer = args[4];
    this.size = parseInt(args[5]);
    this.allocation_type = Object.keys(TfLiteAllocationType)[parseInt(args[6])];
    this.allocation = args[7];
    this.is_variable = args[8];
    this.tensor = args[9];

    // Get Shapes
    this.shape = []
    for (var i = 1; i <= this.dims; i++) {
        var v = this._dims_p.add(4*i).readU32();
        this.shape.push(v);
    }
}

function TfLiteTensor(address) {
    this.type = Object.keys(TfLiteType)[parseInt(address.readU32())];;
    this.data = address.add(1*8).readPointer();
    this.data_raw = []; // Custom, holds data array as uint8
    this.dims = new TfLiteIntArray(address.add(2*8).readPointer())

    this.params = address.add(3*8).readPointer()
    this.allocation_type = Object.keys(TfLiteAllocationType)[parseInt(address.add(4*8).readPointer())];
    this.bytes = parseInt(address.add(5*8).readPointer())
    this.allocation = address.add(6*8).readPointer() // TODO
    this.name = address.add(7*8).readPointer().readCString()
    this.delegate = address.add(8*8).readPointer() // TODO
    this.buffer_handle = address.add(9*8).readPointer() // TODO
    this.data_is_stale = address.add(10*8).readPointer()
    this.is_variable = address.add(11*8).readPointer()
    this.quantization = address.add(12*8).readPointer() // TODO
    this.sparsity = address.add(13*8).readPointer() // TODO
    this.dims_signature = address.add(14*8).readPointer() // TODO
}

Java.perform(function() {
    var lib = Module.findBaseAddress('libgoogle_speech_jni.so');
    console.log("libgoogle_speech_jni!", lib)

    // void TfLiteTensorReset(TfLiteType type, const char* name, TfLiteIntArray* dims,
    //     TfLiteQuantizationParams quantization, char* buffer,
    //     size_t size, TfLiteAllocationType allocation_type,
    //     const void* allocation, bool is_variable,
    //     TfLiteTensor* tensor)
    var TfLiteTensorReset_pointer = 0x0102f180;
    var TfLiteStatus_Subgraph_Invoke = 0x01017ba0;

    var tensors_pointers = [];
    var tensors = []
    try {
        var intercept = Interceptor.attach(lib.add(TfLiteTensorReset_pointer), {
            onEnter: function(args) {
                tensors_pointers.push(args[9])
            },
            onLeave: function(retval) {
            }
        });   
    } catch (error) {
        console.log("Cant hook", error)
    }

    var count = 0;
    try {
        var intercept = Interceptor.attach(lib.add(TfLiteStatus_Subgraph_Invoke), {
            onEnter: function(args) {
                // intercept.detach()
            },
            // Load tensors onLeave to ensure inference has ran
            onLeave: function(retval) {
                console.log("Invoke");

                // Initial load
                if (count == 0) {
                    for(var i in tensors_pointers) {
                        var tensor = new TfLiteTensor(tensors_pointers[i]);
                        tensor.name = i + "-" + tensor.name // Keep track of index
                        tensor.data_is_loaded = false // Custom variable to keep track of loaded data
                        tensors.push(tensor);
                    }
                }

                // TODO: Refactor/optimize
                for(var i = 0; i < tensors.length; i++) {
                    var tensor = tensors[i];

                    if(!tensor.data_is_loaded || tensor.allocation_type != "kTfLiteMmapRo") {
                        var data_pointer = tensor.data.readByteArray(tensor.bytes)
                        var data_raw = new Uint8Array(data_pointer);

                        var data_raw_array = []
                        for(var j = 0; j < data_raw.length; j++) {
                            data_raw_array.push(data_raw[j])
                        }
                        tensors[i].data_raw = data_raw_array // Store data in tensor
                        tensors[i].data_is_loaded = true;
                        console.log("Loaded data ", count, i, tensor.name, tensor.allocation_type, tensor.data_raw.length, tensor.allocation_type != "kTfLiteMmapRo")
                    }
                    else {
                        tensors[i].data_raw = [] // Erase data_raw to save space
                    }
                    console.log({count: count, tensor: tensor})
                }

                count++;
            }
        });   
    } catch (error) {
        console.log("Cant hook", error)
    }
});