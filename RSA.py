from burp import IBurpExtender
from burp import IHttpListener,IMessageEditor
import json
from javax.crypto import Cipher
from javax.crypto.spec import IvParameterSpec, SecretKeySpec
from java.util import Base64
from base64 import b64encode
from java.security import KeyPair, KeyFactory;
from java.security import KeyPairGenerator;
from java.security import PrivateKey;
from java.security import PublicKey;
from java.security.spec import X509EncodedKeySpec;

class BurpExtender(IBurpExtender, IHttpListener):

    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        self.callbacks = callbacks
        
        # set our extension name
        callbacks.setExtensionName("AnoF - RSAEnc")
        
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
        mycityname = y["UserId"]
        fromdateorignal = y["fromDate"]
        orignalenddate =y["toDate"]
        publickey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlTZi1tzZcmvN2jGOMzQNJwqNmoiBH6GqMR56LIuGPzhdxK9wtZdvCQD1/2ZGONPnf38WUd4bahN0Sv0hyz8cFJDwuSU0R6tyXZouSNILT2maWs/vd4V0lFF4YZ15rakggQ9fsdr0lKGzQcQMU8XLl5vZg9HTE+fumiabU1yInX3DubyIv/U2WTST2TsGM/GHgSS4FsCwC00lpjdBBLTRnyv+AMGiV1lta3NTPkA4NzCF2382OsTfaJOZbt2uR/wvlEK/H3pewNr+ePRRLe8bSTBTyMfNS0oimREyXd4070glFYFZgQGASYd1IzJDyK2QuWSHP0eY/6+vOi+dYucHDwIDAQAB"
        encoded = Base64.getDecoder().decode(publickey);

        encryptionCipher = Cipher.getInstance("RSA");
        keyFactory = KeyFactory.getInstance("RSA");

        keySpec = X509EncodedKeySpec(encoded);
        pubkey = keyFactory.generatePublic(keySpec)
        encryptionCipher.init(Cipher.ENCRYPT_MODE,pubkey);
        message = mycityname
        encryptedMessage = encryptionCipher.doFinal(message);
        encryption = b64encode(encryptedMessage);
        encryptedMessage2 = encryptionCipher.doFinal(fromdateorignal);
        encryption2 = b64encode(encryptedMessage2);
        encryptedMessage3 = encryptionCipher.doFinal(orignalenddate);
        encryption3 = b64encode(encryptedMessage3);
        
		
		
		
		y['UserId'] = encryption
        y['fromDate'] = encryption2
        y['toDate'] = encryption3
        y=json.dumps(y)
        self.callbacks.printOutput(str(y))
        
        updatedbody = self._helpers.stringToBytes(str(y))

        
        messageInfo.setRequest(self._helpers.buildHttpMessage(header,updatedbody))

        
        
