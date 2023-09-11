import sys
import os
import argparse
import base64
import inspect
import logging
import warnings

from google.protobuf.json_format import MessageToJson
from google.protobuf.message import Message
import ProtobufModifier

#init logger file using logging module
class ProtobufDencoder:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler('log.txt')
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('Decoder: %(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.protobuf_modifier = ProtobufModifier.ProtobufModifier()
        # stop printing UserWarning messages, since we are using STDOUT and not doing so can get output dirty
        warnings.filterwarnings("ignore", category=UserWarning)
        warnings.filterwarnings("ignore", category=RuntimeWarning)

    def main(self):
        # Parse arguments
        self.logger.info("Parsing Args...\n")
        parser = argparse.ArgumentParser()
        parser.add_argument("--serialized")
        parser.add_argument("--protobuf_definition")
        parser.add_argument("--api_path")
        parser.add_argument("--isRequest")
        args = parser.parse_args()

        # Load protobuf module from specified file
        self.logger.info("Loading protobuf module...\n")

        # Is a request or response
        if args.isRequest == "True":
            isRequest = True
        else:
            isRequest = False

        # Load the protobuf module
        if args.api_path is None:
            self.logger.info("No API path specified, using default\n")
            decoded_protobuf = self.json_to_protobuf_compiled(args.serialized, args.protobuf_definition)
        else:
            self.logger.info("API path specified, using it\n")
            decoded_protobuf = self.protobuf_to_json_descriptor(args.serialized, args.protobuf_definition, args.api_path, isRequest)

        # Print the resulting protobuf
        self.logger.info("Done, returning base64 encoded string\n")
        #self.logger.info(decoded_protobuf)
        self.logger.info(base64.b64encode(decoded_protobuf.encode()).decode())
        print(base64.b64encode(decoded_protobuf.encode()).decode()) # this is the output of the script

    # Convert protobuf to JSON using the descriptor file aka PB file - gRPC
    def protobuf_to_json_descriptor(self, body: str, file_path: str, api_path: str, isRequest: bool)->str:
        self.protobuf_modifier.set_descriptor(file_path)
        self.logger.info("Parsing protobuf string into JSON {}\n".format(api_path))
        self.logger.info("body: {}\n".format(body))
        # print to the log file the base64 decoded body
        self.logger.info("base64 decoded body: {}\n".format(base64.b64decode(body)))
        return self.protobuf_modifier.deserialize(api_path, base64.b64decode(body), isRequest)
    
    #TEST: I think this is the correct way to do it
    # Convert serialized message to JSON using the compiled file aka PY file - protobuf with definitions 
    def protobuf_compiled_to_json(self, protobuf_body: str, file_path: str) -> str:
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

        # Deserialize protobuf
        proto_msg = proto_class()
        self.logger.info("Deserializing protobuf string into structure\n")
        # https://googleapis.dev/python/protobuf/latest/google/protobuf/message.html#google.protobuf.message.Message.ParseFromString
        proto_msg.ParseFromString(protobuf_body)

        self.logger.info("Converting protobuf structure into JSON string\n")
        return MessageToJson(proto_msg)

    #TODO: protobuf decoder withouts definitions using protoc compiler, this will result in a generic protobuf decoder without names

if __name__ == "__main__":
    ProtobufDencoder().main()


