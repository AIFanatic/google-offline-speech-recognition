function AddNodeWithParameters(args) {
    this.inputs = args[1];
    this.outputs = args[2];
    this.intermediates = args[3]
    this.init_data = args[4];
    this.init_data_size = args[5];
    this.builtin_data = args[6];
    this.registration = args[7];
    this.node_index = args[8];
}

Java.perform(function() {

    // TfLiteStatus Subgraph::AddNodeWithParameters(
    //     const std::vector<int>& inputs, const std::vector<int>& outputs,
    //     const std::vector<int>& intermediates, const char* init_data,
    //     size_t init_data_size, void* builtin_data,
    //     const TfLiteRegistration* registration, int* node_index)
    var TfLiteStatus_Subgraph_AddNodeWithParameters = 0x010163a0;

    var lib = Module.findBaseAddress('libgoogle_speech_jni.so');
    console.log("libgoogle_speech_jni!", lib)

    const std_vector_pointer_get_size = new NativeFunction(Module.findExportByName('libinject.so', 'std_vector_pointer_get_size'), 'int', ['pointer'])
    const std_vector_pointer_get_data_pointer = new NativeFunction(Module.findExportByName('libinject.so', 'std_vector_pointer_get_size'), 'pointer', ['pointer'])
    console.log(std_vector_pointer_get_size)
    console.log(std_vector_pointer_get_data_pointer)

    var nodes = []

    try {
        var intercept = Interceptor.attach(lib.add(TfLiteStatus_Subgraph_AddNodeWithParameters), {
            onEnter: function(args) {
                // intercept.detach()

                var node = new AddNodeWithParameters(args)

                console.log(JSON.stringify(node))

                nodes.push(node);

                console.log("std_vector_pointer_get_size", 
                    std_vector_pointer_get_size(node.inputs),
                    std_vector_pointer_get_size(node.outputs)
                ); 

                console.log("std_vector_pointer_get_data_pointer", 
                    std_vector_pointer_get_data_pointer(node.inputs),
                    std_vector_pointer_get_data_pointer(node.outputs)
                ); 

                console.log("inputs data")
                for(var i = 0; i < std_vector_pointer_get_size(node.inputs); i++) {
                    console.log(node.inputs.readPointer().add(i).readInt())
                }

                console.log("outputs data")
                for(var i = 0; i < std_vector_pointer_get_size(node.outputs); i++) {
                    console.log(node.outputs.readPointer().add(i).readInt())
                }

            },
            onLeave: function(retval) {
                console.log("Ret", JSON.stringify(retval))
            }
        });   
    } catch (error) {
        console.log("Cant hook", error)
    }
});