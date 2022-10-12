from burp import IBurpExtender
from burp import IHttpListener
import json
from javax.crypto import Cipher
from javax.crypto.spec import IvParameterSpec, SecretKeySpec
from java.util import Base64
from base64 import b64encode


key = "8080808080808080"
aeskey = SecretKeySpec(key,"AES")
aesIV = IvParameterSpec(key);

class BurpExtender(IBurpExtender, IHttpListener):

    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        self.callbacks = callbacks
        
        # set our extension name
        callbacks.setExtensionName("AnoF - Enc")
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if not messageIsRequest:
            return

        
        httpService = messageInfo.getHttpService()
        req = self._helpers.analyzeRequest(messageInfo)
        getody = req.getBodyOffset()
        header = req.getHeaders()
        self.requestinst = self._helpers.bytesToString(messageInfo.getRequest())
        
        
        
        self.body = self.requestinst[getody:len(self.requestinst)]
        y = json.loads(self.body)
        mycityname = y["json-parameter-name"]
        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.ENCRYPT_MODE, aeskey, aesIV)
        encrypted = cipher.doFinal(mycityname)
        encrdata = b64encode(encrypted)
        
      
        y = {'json-parameter-name':'encrpyted-value'}
        y['json-parameter-name'] = encrdata
        updatedbody = self._helpers.stringToBytes(str(y))

        
        messageInfo.setRequest(self._helpers.buildHttpMessage(header,updatedbody))

        
        
