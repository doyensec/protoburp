import os
import subprocess
import base64
import json
import array
from java.lang import Runtime
from java.lang import System
from java.io import BufferedReader
from java.io import InputStreamReader

class Bridge:
    def __init__(self, base_dir):
        """
        A utility class for bridging between JSON and Protocol Buffers (protobuf) in Python 3.
        
        Args:
            base_dir (str): The base directory path for the utility.
        """
        self._BASE_DIR = base_dir
        self.get_python3_path()

    def get_python3_path(self):
        """
        Retrieves the installation path of Python3 based on the operating system.

        This function executes OS-specific commands to determine the location of Python3:
        - On Windows, it uses the `where` command.
        - On Linux and MacOS, it uses the `which` command.

        If the function is unable to determine the operating system or locate the Python3 installation, it raises an exception.

        This function allow to use python3 from the system and relative libraries, overcoming the Jython environment issues.
        Thanks to this, we can use the latest version of protobuf library.

        Returns:
            str: The path to the Python3 installation.

        Raises:
            Exception: If the operating system is not supported or if the Python3 installation cannot be found.
        """
        cmd = None
        
        os_name = System.getProperty("os.name").lower()
        
        if "win" in os_name:
            cmd = ["cmd.exe", "/c", "where", "python3"]
        elif "nix" in os_name or "nux" in os_name:
            cmd = ["which", "python3"]
        elif "mac" in os_name:
            cmd = ["/bin/sh", "-c", "PATH=/opt/homebrew/bin:$PATH which python3"]
        else:
            raise Exception("Unsupported Operating System")

        process = Runtime.getRuntime().exec(cmd)
        reader = BufferedReader(InputStreamReader(process.getInputStream()))
        line = reader.readLine()

        if line:
            self._PYTHON3_PATH = line
            print("Python 3 path: "+self._PYTHON3_PATH)
        else:
            raise Exception("Python 3 not found")

    def json_to_protobuf_in_python3(self, json_body, api_path, path):
        """
        Convert JSON data to Protocol Buffers (protobuf) format using an external Python 3 script.
        
        Args:
            json_body (dict, bytes, array.array): The JSON data to be converted.
            api_path (str): The API path related to the protobuf definition.
            path (str): Path to the protobuf definition file.
            
        Returns:
            bytes: The data in protobuf format.
        """

        # This trick is needed because Burp Suite apparently return different data type from different components
        if isinstance(json_body, bytes):
            # If json_body is a byte array, decode it to a string
            json_str = json_body.decode("utf-8")
        elif isinstance(json_body, dict):
            # If json_body is a dictionary, convert it to a JSON string
            json_str = json.dumps(json_body)
        elif isinstance(json_body, array.array):
            # If json_body is an array, convert it to a JSON string
            json_str = ''.join(chr(b) for b in json_body)  # Convert byte array to string
        else:
            print("Unsupported json_body type "+str(type(json_body)))

        # Prepare the command to run in Python 3
        cmd = [self._PYTHON3_PATH, os.path.join(self._BASE_DIR, "protobuf-encoder.py"), "--json", json_str, "--protobuf_definition", path]
        if path.endswith(".pb"):
            cmd.append("--api_path")
            cmd.append(str(api_path))
        output = ""
        # Run the command
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print("Subprocess exited with error (status code {}):".format(e.returncode))
            print(e.output.decode())
        
        output = output.decode("utf-8").strip()
        protobuf = base64.b64decode(output)

        return protobuf
    
    def protobuf_to_json_in_python3(self, protobuf, api_path, path, isRequest):
        """
        Convert Protocol Buffers (protobuf) data to JSON format using an external Python 3 script.
        
        Args:
            protobuf (bytes): The protobuf data to be converted.
            api_path (str): The API path related to the protobuf definition.
            path (str): Path to the protobuf definition file.
            isRequest (bool): Flag indicating whether the protobuf is a request or not.
            
        Returns:
            bytes: The data in JSON format.
        """
        if isRequest:
            Request = "True"
        else:
            Request = "False"
        # Prepare the command to run in Python 3
        #TODO: get the right python3 path, is not stright forward under Burp Suite Jython
        cmd = [self._PYTHON3_PATH, os.path.join(self._BASE_DIR, "protobuf-decoder.py"), "--serialized", protobuf, "--protobuf_definition", path, "--isRequest", Request]
        if path.endswith(".pb"):
            cmd.append("--api_path")
            cmd.append(str(api_path))
        output = ""
        # Run the command
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print("Subprocess exited with error (status code {}):".format(e.returncode))
            print(e.output.decode())

        output = output.decode("utf-8").strip()
        json_body = base64.b64decode(output)
        return json_body