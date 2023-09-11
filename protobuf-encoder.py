import sys
import os
import argparse
import base64
import inspect
import ProtobufModifier
import logging
import warnings

from google.protobuf.json_format import Parse
from google.protobuf.message import Message

#init logger file using loggin module
class ProtobufEncoder:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler('log.txt')
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('Encoder: %(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.protobuf_modifier = ProtobufModifier.ProtobufModifier()
        # stop printing UserWarning messages, since we are using STDOUT and not doing so can get output dirty
        warnings.filterwarnings("ignore", category=UserWarning)

    def main(self):
        # Parse arguments
        self.logger.info("Parsing Args...\n")
        parser = argparse.ArgumentParser()
        parser.add_argument("--json")
        parser.add_argument("--protobuf_definition")
        parser.add_argument("--api_path")
        args = parser.parse_args()

        # Load protobuf module from specified file
        self.logger.info("Loading protobuf module...\n")

        # Load the protobuf module
        if args.api_path is None:
            self.logger.info("No API path specified, using default\n")
            serialized_protobuf = self.json_to_protobuf_compiled(args.json, args.protobuf_definition)
        else:
            self.logger.info("API path specified, using it\n")
            serialized_protobuf = self.json_to_protobuf_descriptor(args.json, args.protobuf_definition, args.api_path)

        # Print the resulting protobuf
        self.logger.info("Done, returning base64 encoded string\n")
        self.logger.info(base64.b64encode(serialized_protobuf).decode())
        print(base64.b64encode(serialized_protobuf).decode()) # this is the output of the script

    # Convert JSON to protobuf using the descriptor file aka PB file - gRPC
    def json_to_protobuf_descriptor(self, json_body: str, file_path: str, api_path: str)->bytes:
        self.protobuf_modifier.set_descriptor(file_path)
        self.logger.info("Parsing JSON string into protobuf {}\n".format(api_path))
        return self.protobuf_modifier.serialize(api_path, json_body)

    # Convert JSON to protobuf using the compiled file aka PY file - protobuf with definitions    
    def json_to_protobuf_compiled(self, json_body: str, file_path: str)->bytes:
            sys.path.insert(0, os.path.dirname(file_path))

            # Get the filename with the extension
            base_name = os.path.basename(file_path)

            # Remove the extension
            class_name = os.path.splitext(base_name)[0]
            proto_module = __import__(class_name)

            proto_class = None

            for name, obj in inspect.getmembers(proto_module):
                if inspect.isclass(obj) and issubclass(obj, Message):
                    proto_class = getattr(proto_module, name)
                    break

            # Convert JSON to protobuf
            proto_msg = proto_class()
            self.logger.info("Parsing JSON string into protobuf\n")
            Parse(json_body, proto_msg)

            self.logger.info("Serializing protobuf structure to string\n")
            return proto_msg.SerializeToString()
    

if __name__ == "__main__":
    ProtobufEncoder().main()