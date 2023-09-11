CONTENT_PROTOBUF = [
    'application/protobuf',
    'application/x-protobuf',
    'application/x-protobuffer',
    'application/x-protobuffer; charset=utf-8',
    'application/octet-stream', #TODO: this needs to be handled differently
    'application/grpc-web+proto',
    'application/grpc-web+proto; charset=utf-8',
    'application/grpc-web-text',
    'application/grpc-web-text; charset=utf-8',
    'application/vnd.google.protobuf',
    'application/vnd.google.protobuf; charset=utf-8',
    'application/grpc',
    'application/grpc+proto',
    'application/grpc+protobuf'
]

def getResponseBody(self, requestResponse):
    analyzedResponse = self._helpers.analyzeResponse(requestResponse.getResponse())
    return self._helpers.bytesToString(requestResponse.getResponse()[analyzedResponse.getBodyOffset():])

    
def getRequestBody(self, requestRequest):
    analyzedRequest = self._helpers.analyzeRequest(requestRequest.getRequest())
    return self._helpers.bytesToString(requestRequest.getRequest()[analyzedRequest.getBodyOffset():])