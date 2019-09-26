<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Tools;

class RSA
{
	public function sign($keyObj, $strData, $algo=OPENSSL_ALGO_SHA1)
	{
		$valid	= openssl_sign($strData, $sig, array($keyObj->get(), $keyObj->getPassPhrase()), $algo);
		if ($valid === true) {
			//bin data
			return $sig;
		} else {
			throw new \Exception("Failed to sign input");
		}
	}
	public function verifySign($keyObj, $strData, $sig, $algo=OPENSSL_ALGO_SHA1)
	{
	    $valid	= @openssl_verify($strData, $sig, $keyObj->get(), $algo);
	    if ($valid === 1) {
	        return true;
	    } elseif ($valid === 0) {
	        return false;
	    } else {
	        //-1 return on failure
	        throw new \Exception("Failed to validate signature");
	    }
	}
	public function createPrivateKey($bits=4096, $passPhrase=null)
	{
		$keyConf = array(
				"private_key_bits"	=> $bits,
				"private_key_type"	=> OPENSSL_KEYTYPE_RSA,
		);
		
		$res	= openssl_pkey_new($keyConf);
		if (is_resource($res) === true) {
			openssl_pkey_export($res, $pKey, $passPhrase);
			
			$rObj	= \MTM\Encrypt\Factories::getRSA()->getPrivateKey($pKey);
			$rObj->setPassPhrase($passPhrase);
			
			return $rObj;
	
		} else {
			throw new \Exception("Invalid input");
		}
	}
	public function getPublicKeyFromPrivateKey($keyObj)
	{
	    $rObj    = $this->getPrivateKeyDetail($keyObj);
	    return $rObj->publicKey;
	}
	public function getDecryptedPrivateKey($keyObj)
	{
		if ($keyObj->getPassPhrase() !== null) {
			
		    $res      = $this->getPrivateAsResource($keyObj);
			$valid    = openssl_pkey_export($res, $pKey);
			if ($valid === false) {
				throw new \Exception("Failed to extract private");
			} else {
				return \MTM\Encrypt\Factories::getRSA()->getPrivateKey($pKey);
			}

		} else {
			//not encrypted to start with 
			return $keyObj;
		}
	}
	public function getEncryptedPrivateKey($keyObj, $newPassPhrase)
	{
		if ($keyObj->getPassPhrase() != $newPassPhrase) {
			
		    $res      = $this->getPrivateAsResource($keyObj);
			$valid	  = openssl_pkey_export($res, $pKey, $newPassPhrase);
			if ($valid === false) {
				throw new \Exception("Failed to extract private");
			} else {
				
				return \MTM\Encrypt\Factories::getRSA()->getPrivateKey($pKey, $newPassPhrase); 
			}

		} else {
			//already encrypted with the same key
			//should we really test is the key is encrypted at all?
			return $keyObj;
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
		$valid	= openssl_public_encrypt($strData, $encData, $keyObj->get(), $pad);
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
			throw new \Exception("Failed to encrypt");
		}
	}
	public function encryptTest($keyObj, $pad=OPENSSL_PKCS1_PADDING)
	{
	    try {
	        
	        $strData   = "";
	        $append    = "A";
	        $len       = 0;
	        while(true) {
	            $strData   .=  $append;
	            $this->encrypt($keyObj, $strData, $pad);
	            $len       = strlen($strData);
	        }

	    } catch (\Exception $e) {
	        //reached max
	        return $len;
	    }
	}
	
	public function decrypt($keyObj, $strData)
	{
		$valid	= openssl_private_decrypt($strData, $decData, array($keyObj->get(), $keyObj->getPassPhrase()));
		if ($valid === true) {
			return $decData;
		} else {
			throw new \Exception("Failed to decrypt");
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
            throw new \Exception("Failed to extract details for private key");
        }
	}
	private function getPrivateAsResource($keyObj)
	{
	    $res	= openssl_pkey_get_private($keyObj->get(), $keyObj->getPassPhrase());
	    if (is_resource($res) === true) {
	        return $res;
	    } else {
	        throw new \Exception("Failed to extract private key, maybe invalid pass phrase");
	    }
	}
}