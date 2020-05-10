import importlib.util, sys, glob
from protos_python.speech.greco3.pipeline.pipeline_pb2 import PipelineDef

# Dodgy way of loading all the proto files
modules = glob.glob("./protos_python/**/*.py", recursive=True)
for module in modules:
    try:
        spec = importlib.util.spec_from_file_location("module.name", module)
        foo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(foo)
    except Exception as identifier:
        pass

pipeline = PipelineDef()

f = open(sys.argv[1], "rb")
pipeline.ParseFromString(f.read())

print(pipeline)

f = open(sys.argv[2], "wb")
f.write(pipeline.SerializeToString())
f.close()