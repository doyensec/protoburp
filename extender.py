import json
import inspect
import base64
import os
import sys

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IHttpListener
from burp import ITab
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JFileChooser
from java.awt import FlowLayout
from tab import Tab
import Bridge # bridge between python2 and python3
import ProtobufTab # custom tab
import utils

# Add correct directory to sys.path
# legacy code to be removed since we are using system python now
_BASE_DIR = os.path.abspath(
    os.path.dirname(inspect.getfile(inspect.currentframe()))
)

sys.path.insert(0, _BASE_DIR + "/deps/protobuf/python/")

EXTENSION_NAME = "ProtoBurp++"

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):
    def __init__(self):
        self.Bridge = Bridge.Bridge(_BASE_DIR)

    # Implement IBurpExtender methods
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object (Burp Extensibility Feature)
        self._callbacks = callbacks

        # set our extension name that will display in the Extender tool when loaded
        self._callbacks.setExtensionName(EXTENSION_NAME)

        # register ourselves as an HTTP listener
        self._callbacks.registerHttpListener(self)

        # register ourselves as a custom IMessageEditorTabFactory 
        self._callbacks.registerMessageEditorTabFactory(self)

        # get burp helper functions
        self._helpers = self._callbacks.getHelpers()

        self.suite_tab = Tab(self, callbacks)

        # Add the custom tab
        callbacks.addSuiteTab(self.suite_tab)

    def getTabCaption(self):
        return "ProtoBurp++"

    def getUiComponent(self):
        return self._jPanel

    def file_chooser(self, event):
        chooser = JFileChooser()
        action = chooser.showOpenDialog(self._jPanel)

        if action == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()


    #TODO: create functions to retrieve data from request and response objects to keep the code clean eg. getResponseBody
    # Implement IHttpListener methods
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only continue if the extension is enabled
        if not self.suite_tab.protoburp_enabled:
            return
        # Get the HTTP service for the request
        httpService = messageInfo.getHttpService()

        # Convert the request to a IRequestInfo object
        requestInfo = self._helpers.analyzeRequest(httpService, messageInfo.getRequest())
        # requestInfo is an IRequestInfo object
        headers = requestInfo.getHeaders()

        # Convert header names to lower case for case-insensitive comparison
        header_names = [header.split(":")[0].lower() for header in headers]

        # Only process if the ProtoBurp header exists in the request, this trick is need for the scanner/repeater
        if not "protoburp" in header_names:
            return


        # Only process requests for JSON content
        if messageIsRequest:

            # Get the body of the request
            # body = messageInfo.getRequest()[requestInfo.getBodyOffset():]
            # Convert the body from bytes to string
            #body_string = body.tostring().decode()
            body_string = utils.getRequestBody(messageInfo) 
            # Convert the string to a JSON object
            json_body = json.loads(body_string)
            # Convert the JSON to Protobuf
            protobuf = self.Bridge.json_to_protobuf_in_python3(json_body, requestInfo.getUrl().getPath(), str(self.suite_tab.selectedFilePath))

            # Check if the request is gRPC-Web-Text, if so, don't encode the body.
            if any("grpc-web-text" in header.lower() for header in headers):
                protobuf = base64.b64encode(protobuf)

            # Create a new HTTP message with the Protobuf body
            new_message = self._helpers.buildHttpMessage(headers, protobuf)
            # Update the request in the messageInfo object
            messageInfo.setRequest(new_message)

        else:
            # Convert the request to a IRequestInfo object
            responseInfo = self._helpers.analyzeRequest(httpService, messageInfo.getResponse())
            # responseInfo is an IRequestInfo object
            headers = responseInfo.getHeaders()

            # Convert the request to a IRequestInfo object to get the URL fot the API path
            requestInfo = self._helpers.analyzeRequest(httpService, messageInfo.getRequest())

            # Check if the response is Protobuf
            parse = any(
                        (header.split(":")[1].strip().lower() if ":" in header else header.lower())
                        in utils.CONTENT_PROTOBUF for header in headers
                    )

            if parse:
                body = self.getResponseBody(messageInfo)

                # Check if any header has "grpc-web-text". If so, don't encode the body.
                encode = not any("grpc-web-text" in header.lower() for header in headers)
                if encode:
                    body = base64.b64encode(body)
                    
                json_body = self.Bridge.protobuf_to_json_in_python3(body, requestInfo.getUrl().getPath(), str(self.suite_tab.selectedFilePath), False)
                
                # If needed in the future, you can uncomment this to add a new header.
                # headers.append("Protoburp-Response: True")

                # Create a new HTTP message with the JSON body and update it in the messageInfo object.
                new_message = self._helpers.buildHttpMessage(headers, json_body)
                messageInfo.setResponse(new_message)



    # Implement IMessageEditorTabFactory methods
    def createNewInstance(self, controller, editable):
        return ProtobufTab.ProtobufTab(controller, editable, self._callbacks, self.Bridge, self.suite_tab)