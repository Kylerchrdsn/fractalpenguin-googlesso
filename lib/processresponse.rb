require "openssl"
require "openssl/x509"
require "base64"
require "rexml/document"
require "rexml/xpath"
require "zlib"
require "digest/sha1"
require "xmlcanonicalizer"

include REXML
include OpenSSL

  class XmlProcessResponse
    attr_accessor :acs, :encodedresponse, :authenticateform, :logger
      
    # Constructor @.@
    #**********************************************************************************
    def initialize(certificate_path, private_key_path, crypt_type = "rsa", issuer = "", issueinstant = "", providername = "", acs = "", relayState = "")
      @certificate_path = certificate_path
      @private_key_path = private_key_path
      @crypt_type = crypt_type
      @issuer = issuer
      @issueinstant = issueinstant
      @providername = providername
      @acs = acs
      @relayState = relayState
      @requestID = ""

      libpath = "#{Gem.dir}/gems/fractalpenguin-googlesso-#{FractalPenguinGoogleSSO::VERSION}/lib"
      @signature_template_path = "#{libpath}/SignatureTemplate.xml"
      @response_template_path = "#{libpath}/SamlResponseTemplate.xml"
      
      @encodedresponse = ""
      @authenticateform = ""

      @logger = nil#Logger.new("response.log")
      #@logger.level = Logger::DEBUG
    end
    
    # Process the SAML request, generate a response, and generate an auth form @.@
    #**********************************************************************************
    def process_response(samlRequest, relayState, username, form_only = nil)
      xml_string = decodeAuthnRequestXML(samlRequest)
      getRequestAttributes(xml_string)
      
      samlResponse = createSamlResponse(username)   
      
      @logger.debug("\nSAML Response\n" + samlResponse.to_s()) if @logger
      
      signedResponse = signXML(samlResponse)

      @logger.debug("\nSigned Response\n" + signedResponse.to_s()) if @logger

      @encodedresponse = Base64.encode64(signedResponse)
      
      unless form_only
        @authenticateform = "<html>
                               <head>
                                 <script type=\"text/javascript\"> 
			                             var t = setTimeout(\"document.acsForm.submit();\", 0);
		                             </script>
                               </head>
                               
                               <body>
                                 <form name='acsForm' id='acsForm' action='#{@acs}' method='post'>
			                             <input type='hidden' name='SAMLResponse' value=\"#{signedResponse}\" />
			                             <input type='hidden' name='RelayState' value=\"#{relayState}\" />
                                 </form>
                                 <br/>
                                 <br/>
                                 <br/>
                                 <center>
                                   <h2>Redirecting...</h2>
                                 </center>
                               </body>
                             </html>"
      else
        @authenticateform = "<form name='acsForm' id='acsForm' action='#{@acs}' method='post'>
			                         <input type='hidden' name='SAMLResponse' value=\"#{signedResponse}\" />
			                         <input type='hidden' name='RelayState' value=\"#{relayState}\" />
                             </form>"
      end
    end

    # Generate a response, and generate an auth form @.@
    #**********************************************************************************
    def process_response_wo_request(username, form_only = nil)
      samlResponse = createSamlResponse(username)   
      
      @logger.debug("\nSAML Response\n" + samlResponse.to_s()) if @logger
      
      signedResponse = signXML(samlResponse)

      @logger.debug("\nSigned Response\n" + signedResponse.to_s()) if @logger

      @encodedresponse = Base64.encode64(signedResponse)
      
      unless form_only
        @authenticateform = "<html>
                               <head>
                                 <script type=\"text/javascript\"> 
			                             var t = setTimeout(\"document.acsForm.submit();\", 0);
		                             </script>
                               </head>
                               
                               <body>
                                 <form name='acsForm' id='acsForm' action='#{@acs}' method='post'>
			                             <input type='hidden' name='SAMLResponse' value=\"#{signedResponse}\" />
			                             <input type='hidden' name='RelayState' value=\"#{@relayState}\" />
                                 </form>
                                 <br/>
                                 <br/>
                                 <br/>
                                 <center>
                                   <h2>Redirecting...</h2>
                                 </center>
                               </body>
                             </html>"
      else
        @authenticateform = "<form name='acsForm' id='acsForm' action='#{@acs}' method='post'>
			                         <input type='hidden' name='SAMLResponse' value=\"#{signedResponse}\" />
			                         <input type='hidden' name='RelayState' value=\"#{@relayState}\" />
                             </form>"
      end
    end
    
    # private
    
    # Decode the SAML request @.@
    #**********************************************************************************
    def decodeAuthnRequestXML(encodedRequestXmlString)
      unzipper = Zlib::Inflate.new( -Zlib::MAX_WBITS )
      return unzipper.inflate(Base64.decode64( encodedRequestXmlString ))
    end
    
    # Get needed attributes from the decoded SAML request @.@
    #**********************************************************************************
    def getRequestAttributes(xmlString)
      doc = Document.new( xmlString )
      @issueinstant = doc.root.attributes["IssueInstant"]
      @providername = doc.root.attributes["ProviderName"]
      @acs = doc.root.attributes["AssertionConsumerServiceURL"]
      @requestID = doc.root.attributes["ID"]
    end
    
    # Generate SAML response @.@
    #**********************************************************************************
    def createSamlResponse(authenticatedUser)
      current_time = Time.new().utc().strftime("%Y-%m-%dT%H:%M:%SZ")
      # 20 minutes after issued time
      notOnOrAfter = (Time.new().utc()+60*20).strftime("%Y-%m-%dT%H:%M:%SZ")
  
      samlResponse = ""
      File.open(@response_template_path).each { |line|
        samlResponse += line
      }
      
      samlResponse.gsub!("<USERNAME_STRING>", authenticatedUser)
      samlResponse.gsub!("<RESPONSE_ID>",  generateUniqueHexCode(42))
      samlResponse.gsub!("<ISSUE_INSTANT>",  current_time)
      samlResponse.gsub!("<AUTHN_INSTANT>",  current_time)
      samlResponse.gsub!("<NOT_BEFORE>",  @issueinstant)
      samlResponse.gsub!("<NOT_ON_OR_AFTER>",  notOnOrAfter)
      samlResponse.gsub!("<ASSERTION_ID>",  generateUniqueHexCode(42))
      (@requestID == "") ? samlResponse.gsub!("InResponseTo=\"<REQUEST_ID>\"", @requestID) : samlResponse.gsub!("<REQUEST_ID>", @requestID)
      samlResponse.gsub!("<RSADSA>", @crypt_type)
      samlResponse.gsub!("<DESTINATION>", @acs)
      samlResponse.gsub!("<ISSUER_DOMAIN>", @issuer)
      
      return samlResponse
    end
    
    # Sign the SAML response @.@
    #**********************************************************************************
    def signXML(xml)
      signature = ""
      File.open(@signature_template_path).each { |line|
        signature += line
      }
    
      document = Document.new(xml)
      sigDoc = Document.new(signature)

      # 3. Apply digesting algorithms over the resource, and calculate the digest value.
      digestValue = calculateDigest(document)
  
      # 4. Enclose the details in the <Reference> element.
      # 5. Collect all <Reference> elements inside the <SignedInfo> element. Indicate the canonicalization and signature methodologies.
      digestElement = XPath.first(sigDoc, "//DigestValue")
      digestElement.add_text(digestValue)

      # 6. Canonicalize contents of <SignedInfo>, apply the signature algorithm, and generate the XML Digital signature.
      signedElement = XPath.first(sigDoc, "//SignedInfo")
      signatureValue = calculateSignatureValue(signedElement)

      # 7. Enclose the signature within the <SignatureValue> element.
      signatureValueElement = XPath.first(sigDoc, "//SignatureValue")
      signatureValueElement.add_text(signatureValue)

      # 8. Add relevant key information, if any, and produce the <Signature> element.
      cert = ""
      File.open(@certificate_path).each { |line|
        cert += line
      }
      
      cert.sub!(/.*BEGIN CERTIFICATE-----\s*(.*)\s*-----END CERT.*/m, '\1')
  
      certNode = XPath.first(sigDoc, "//X509Certificate")
      certNode.add_text(cert)

      # 9. put it all together
      status_child = document.elements["//samlp:Status"]
      status_child.parent.insert_before(status_child, sigDoc.root)
      retval = document.to_s()
      
      return retval
    end
    
    # Generate Signature @.@
    #**********************************************************************************
    def calculateSignatureValue(element)
      element.add_namespace("http://www.w3.org/2000/09/xmldsig#")
      element.add_namespace("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
      element.add_namespace("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")

      canoner = XmlCanonicalizer.new(false, true)
      canon_element = canoner.canonicalize(element)
      
      if @crypt_type == "rsa"
        pkey = PKey::RSA.new(File::read(@private_key_path))
      elsif @crypt_type == "dsa"
        pkey = PKey::DSA.new(File::read(@private_key_path))
      end
      
      signature = Base64.encode64(pkey.sign(OpenSSL::Digest::SHA1.new, canon_element.to_s.chomp).chomp).chomp

      element.delete_attribute("xmlns")
      element.delete_attribute("xmlns:samlp")
      element.delete_attribute("xmlns:xenc")
      return signature
    end
    
    # Apply digesting algorithms over the resource, and calculate the digest value @.@
    #**********************************************************************************
    def calculateDigest(element)
      canoner = XmlCanonicalizer.new(false, true)
      canon_element = canoner.canonicalize(element)
      
      element_hash = Base64.encode64(Digest::SHA1.digest(canon_element.to_s.chomp).chomp).chomp
      
      return element_hash
    end
    
    # Create response ID @.@
    #**********************************************************************************
    def generateUniqueHexCode( codeLength )
      validChars = ("A".."F").to_a + ("0".."9").to_a
      length = validChars.size
      
      validStartChars = ("A".."F").to_a
      startLength = validStartChars.size
      
      hexCode = ""
      hexCode << validStartChars[rand(startLength-1)]
      
      1.upto(codeLength-1) { |i| hexCode << validChars[rand(length-1)] }
        
      return hexCode
    end
  end
