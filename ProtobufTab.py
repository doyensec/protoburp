import base64
import utils
from burp import IMessageEditorTab

class ProtobufTab(IMessageEditorTab):

    def __init__(self, controller, editable, callbacks, Bridge, suite_tab):

        # We don't need this object for now
        self._controller = controller

        # keep a reference to our callbacks object (Burp Extensibility Feature)
        self._callbacks = callbacks

        # get burp helper functions
        self._helpers = self._callbacks.getHelpers()

        # create a text tab
        self._tab = self._callbacks.createTextEditor()
        self._tab.setEditable(editable)

        # recipe Bridge object
        self.Bridge = Bridge

        # recipe suite_tab object
        self.suite_tab = suite_tab


    def getTabCaption(self):
        return "ProtoBurp++"

    def getUiComponent(self):
        return self._tab.getComponent()

    def isEnabled(self, content, isRequest):
        # Here you need to implement the logic to enable/disable your tab

        # access protoburp_enabled flag from tab
        #if not self.suite_tab.protoburp_enabled:
        #    return False

        # content -> the HTTP request in byte array
        # isRequest -> boolean that tells you if it's a request or a response
        if isRequest:
            messageInfo = self._helpers.analyzeRequest(content)
        else:
            # IResponseInfo
            messageInfo = self._helpers.analyzeResponse(content)

        # messageInfo is an IRequestInfo object
        headers = messageInfo.getHeaders()
        #TODO: check if the content is protobuf with extensive header checking
        return any(
                (header.split(":")[1].strip().lower() if ":" in header else header.lower())
                in utils.CONTENT_PROTOBUF for header in headers
                )


    def setMessage(self, content, isRequest):

        # Make a copy of the content. Can be useful in the getMessage method
        self._current_content = content

        # I need this later to check if the message is a request or a response
        self._isRequest = isRequest

        # content -> the HTTP request in byte array
        # isRequest -> boolean that tells you if it's a request or a response
        if isRequest:
            messageInfo = self._helpers.analyzeRequest(content)
        else:
            # IResponseInfo
            messageInfo = self._helpers.analyzeResponse(content)

        body = content[messageInfo.getBodyOffset():].tostring()
        # messageInfo is an IRequestInfo object
        headers = messageInfo.getHeaders()

        if not any("grpc-web-text" in header.lower() for header in headers): # gRPC-Web-Text is always base64 encoded, we want to encode only if it's not
            body = base64.b64encode(body)

        # we don't have access to the request in the response, but we have access to the controller
        # so we can get the selected api path from there
        httpService = self._controller.getHttpService()
        requestInfo = self._helpers.analyzeRequest(httpService, self._controller.getRequest())
        deserializedBody = self.Bridge.protobuf_to_json_in_python3(body, requestInfo.getUrl().getPath(), str(self.suite_tab.selectedFilePath), isRequest)

        # Set the content of the tab
        self._tab.setText(deserializedBody)


    def getMessage(self):

        # Get the content of the tab
        tab_content = self._tab.getText()

        # This is called when you exit your tab or when you send the request from your tab if the tab is editable.

        # You don't need to check if there have been any changes, already done automatically by the isModified method.
        if self.isModified() and self._isRequest and tab_content not in ["", None]:
            messageInfo = self._helpers.analyzeRequest(self._current_content)

            # we don't have access to the request in the response, but we have access to the controller
            # so we can get the selected api path from there
            httpService = self._controller.getHttpService()
            headers = messageInfo.getHeaders()

            requestInfo = self._helpers.analyzeRequest(httpService, self._controller.getRequest())
            serializedBody = self.Bridge.json_to_protobuf_in_python3(tab_content, requestInfo.getUrl().getPath(), str(self.suite_tab.selectedFilePath))

            #TODO: define utility function for this
            if any("grpc-web-text" in header.lower() for header in headers):
                serializedBody = base64.b64encode(serializedBody)


            return self._helpers.buildHttpMessage(headers, serializedBody)
            


    def isModified(self):
        return self._tab.isTextModified()

    def getSelectedData(self):    
        return self._tab.getSelectedText()
