<?php
//� 2019 Martin Peter Madsen
namespace MTM\Encrypt\Tools;

class RSA
{
	protected $_sslCnfPath=null;
	
	public function sign($keyObj, $strData, $algo=OPENSSL_ALGO_SHA256)
	{
		if ($keyObj instanceof \MTM\Encrypt\Models\RSA\PrivateKey === true) {
			$valid	= openssl_sign($strData, $sig, array($keyObj->get(), $keyObj->getPassPhrase()), $algo);
		} else {
			throw new \Exception("Not handled for key type");
		}
		
		if ($valid === true) {
			//bin data
			return $sig;
		} else {
			throw new \Exception("Failed to sign input: " . openssl_error_string());
		}
	}
	public function verifySign($keyObj, $strData, $sig, $algo=OPENSSL_ALGO_SHA256)
	{
		if ($keyObj instanceof \MTM\Encrypt\Models\RSA\PublicKey === true) {
			$valid	= @openssl_verify($strData, $sig, $keyObj->get(), $algo);
		} elseif ($keyObj instanceof \MTM\Encrypt\Models\RSA\PrivateKey === true) {
			$valid	= @openssl_verify($strData, $sig, $keyObj->getPublicKey()->get(), $algo);
		} else {
			throw new \Exception("Not handled for key type");
		}
	    if ($valid === 1) {
	        return true;
	    } elseif ($valid === 0) {
	        return false;
	    } else {
	        //-1 return on failure
	        throw new \Exception("Failed to validate signature: " . openssl_error_string());
	    }
	}
	public function createPrivateKey($bits=4096, $passPhrase=null)
	{
		$keyConf = array(
				"private_key_bits"	=> $bits,
				"private_key_type"	=> OPENSSL_KEYTYPE_RSA,
		);
		
		$rData	= openssl_pkey_new($keyConf);
		if (
			$rData instanceof \OpenSSLAsymmetricKey === true
			|| is_resource($rData) === true
		) {
			openssl_pkey_export($rData, $pKey, $passPhrase);
			$rObj	= \MTM\Encrypt\Factories::getRSA()->getPrivateKey($pKey);
			$rObj->setPassPhrase($passPhrase);
			
			return $rObj;
	
		} else {
			throw new \Exception("Failed to generate private RSA key", 5555);
		}
	}
	public function getPublicKeyFromPrivateKey($keyObj)
	{
	    $rObj    = $this->getPrivateKeyDetail($keyObj);
	    return $rObj->publicKey;
	}
	public function getDecryptedPrivateKey($keyObj)
	{
		//will duplicate the key
		$res	= $this->getPrivateAsResource($keyObj);
		$valid	= openssl_pkey_export($res, $pKey, null, array("config" => $this->getOpenSslPath()));
		if ($valid === false) {
			throw new \Exception("Failed to extract private");
		} else {
			return \MTM\Encrypt\Factories::getRSA()->getPrivateKey($pKey);
		}
	}
	public function getEncryptedPrivateKey($keyObj, $newPassPhrase)
	{
		//will duplicate the key
		$res      = $this->getPrivateAsResource($keyObj);
		$valid	  = openssl_pkey_export($res, $pKey, $newPassPhrase);
		if ($valid === false) {
			throw new \Exception("Failed to extract private");
		} else {
			return \MTM\Encrypt\Factories::getRSA()->getPrivateKey($pKey, $newPassPhrase);
		}
	}
	public function getPrivateKeyDetail($keyObj)
	{  
	    $res      = $this->getPrivateAsResource($keyObj);
        $detail	  = openssl_pkey_get_details($res);
        if ($detail !== false) {
            
            if (isset($detail["key"]) === false || strlen($detail["key"]) < 1) {
                throw new \Exception("Failed to extract public key, maybe invalid pass phrase");
            }
            
            $rObj               = new \stdClass();
            $rObj->bits         = $detail["bits"];
            
            if (array_key_exists("rsa", $detail) === true) {
                $rObj->type         = "RSA";
                $rObj->publicKey    = \MTM\Encrypt\Factories::getRSA()->getPublicKey($detail["key"]);
            } elseif (array_key_exists("ec", $detail) === true) {
                $rObj->type         = "ECC";
                $rObj->publicKey    = \MTM\Encrypt\Factories::getECC()->getPublicKey($detail["key"]);
                //has curve too
            } else {
                $rObj->type         = "UNKNOWN";
                $rObj->publicKey    = null;
            }
            
            return $rObj;
            
        } else {
            throw new \Exception("Failed to extract details for private key");
        }
	}
	public function createKeyPair($bits=4096, $passPhrase=null)
	{
		$rObj			= new \stdClass();
		$rObj->private	= $this->createPrivateKey($bits, $passPhrase);
		$rObj->public	= $this->getPublicKeyFromPrivateKey($rObj->private);	
		
		return $rObj;
	}
	public function getPEM($keyObj)
	{
		//return a PEM certificate 
		$tempKey	= \MHT\Factories::getFileSystems()->getSessionFile("key");
		$tempKey->setContent($keyObj->get());
		
		$tempPem	= \MHT\Factories::getFileSystems()->getSessionFile("pem");
		$cmdStr		= "openssl rsa -in '".$tempKey->getPathAsString()."' -out '".$tempPem->getPathAsString()."'";
		
		//need an interactive shell to fill in the details
		$shellObj	= \MHIT\Factories::getDevices()->getShell("shared");
		
		//need to deal with fail case
		if ($keyObj->getPassPhrase() === null) {
			//without a passphrase the shell exits without needing input
			$shellObj->exeCmd($cmdStr);
		} else {
			//enter passphrase
			$shellObj->exeCmd($cmdStr, $tempKey->getName() . ":");
			$shellObj->exeCmd($keyObj->getPassPhrase());
		}

		return \MTM\Encrypt\Factories::getRSA()->getPrivateKey(trim($tempPem->getContent()));
	}
	public function encrypt($keyObj, $strData, $pad=OPENSSL_PKCS1_PADDING)
	{
		if ($keyObj instanceof \MTM\Encrypt\Models\RSA\PrivateKey === true) {
			$valid	= openssl_private_encrypt($strData, $encData, array($keyObj->get(), $keyObj->getPassPhrase()), $pad);
		} elseif ($keyObj instanceof \MTM\Encrypt\Models\RSA\PublicKey === true) {
			$valid	= openssl_public_encrypt($strData, $encData, $keyObj->get(), $pad);
		} else {
			throw new \Exception("Not handled for key type");
		}

		if ($valid === true) {
			return $encData;
		} else {
			
			//if you use pad: OPENSSL_NO_PADDING, you must add padding yourself, i do not know where the bounderies are
			
		    //key size dictates how much data can be encrypted by a key
		    //2048 == 245 chars
			//4096 == 501 chars
		    //8192 == 1013 chars
		    //16384 == 2037 chars
		    //32768 == 0 chars (refuses to encrypt)
		    //run $this->encryptTest($key); to see max is posible if you need other sizes
			throw new \Exception("Failed to encrypt: ". openssl_error_string());
		}
	}
	public function decrypt($keyObj, $strData, $pad=OPENSSL_PKCS1_PADDING)
	{
		if ($keyObj instanceof \MTM\Encrypt\Models\RSA\PrivateKey === true) {
			$valid	= openssl_private_decrypt($strData, $decData, array($keyObj->get(), $keyObj->getPassPhrase()), $pad);
		} elseif ($keyObj instanceof \MTM\Encrypt\Models\RSA\PublicKey === true) {
			$valid	= openssl_public_decrypt($strData, $decData, $keyObj->get(), $pad);
		} else {
			throw new \Exception("Not handled for key type");
		}
		if ($valid === true) {
			return $decData;
		} else {
			throw new \Exception("Failed to decrypt: " . openssl_error_string());
		}
	}
	public function getPublicAsSSH($pkeyObj)
	{
	    //input private key
	    $res       = $this->getPrivateAsResource($pkeyObj);
	    $detail    = openssl_pkey_get_details($res);
        if ($detail !== false) {
            
            //https://stackoverflow.com/questions/6648337/generate-ssh-keypair-form-php
            $rData   = "";
            $rData  .= pack("N", 7) . "ssh-rsa";
            
            $eData  = $detail["rsa"]["e"];
            $eLen   = strlen($eData);
            if (ord($eData[0]) & 0x80) {
                $eLen++;
                $eData   = "\x00" . $eData;
            }
            $rData  .= pack("Na*", $eLen, $eData);
            
            $nData  = $detail["rsa"]["n"];
            $nLen   = strlen($nData);
            if (ord($nData[0]) & 0x80) {
                $nLen++;
                $nData   = "\x00" . $nData;
            }
            $rData   .= pack("Na*", $nLen, $nData);
            $encKey   = "ssh-rsa " . base64_encode($rData);

            return \MTM\Encrypt\Factories::getRSA()->getPublicSshKey($encKey);
            
        } else {
            throw new \Exception("Failed to extract details for private key", 5555);
        }
	}
	private function getOpenSslPath()
	{
		if ($this->_sslCnfPath === null) {
			//had to create a custom config file because centos8 would error
			//when extracting the private key using openssl_pkey_export:
			//openssl_error_string() -> "error:0E079065:configuration file routines:DEF_LOAD_BIO:missing equal sign"
			
			$sslObj				=  \MTM\Encrypt\Factories::getTools()->getOpenSsl();
			$tmpFile			= \MTM\FS\Factories::getFiles()->getTempFile("cnf");
			$tmpFile->setContent(implode("\n", $sslObj->getRSA()));
			$this->_sslCnfPath	= $tmpFile->getPathAsString();
		}
		return $this->_sslCnfPath;
	}
	private function getPrivateAsResource($keyObj)
	{
		$rData	= openssl_pkey_get_private($keyObj->get(), $keyObj->getPassPhrase());
	    if (
			$rData instanceof \OpenSSLAsymmetricKey
			|| is_resource($rData) === true
		) {
			return $rData;
	    } else {
	        throw new \Exception("Failed to extract private key, maybe invalid pass phrase", 5555);
	    }
	}
}