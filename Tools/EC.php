<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Tools;

class EC
{
	protected $_sslCnfPath=null;
	
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
	public function createPrivateKey($curve="secp256k1", $passPhrase=null)
	{
		$keyConf = array(
				"private_key_type"	=> OPENSSL_KEYTYPE_EC,
				"curve_name"		=> $curve
		);
		$res	= openssl_pkey_new($keyConf);
		if (is_resource($res) === true) {
			openssl_pkey_export($res, $pKey, $passPhrase);
			openssl_free_key($res);
			$rObj	= \MTM\Encrypt\Factories::getEC()->getPrivateKey($pKey);
			$rObj->setPassPhrase($passPhrase);
			return $rObj;
	
		} else {
			throw new \Exception("Invalid input: " . openssl_error_string());
		}
	}
	public function getPrivateKeyFromHex($str)
	{
		//example:
		//$str	= "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
		//echo 302e0201010420 18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725 a00706052b8104000a | xxd -r -p | openssl ec -inform d
		//src: https://stackoverflow.com/questions/48101258/how-to-convert-an-ecdsa-key-to-pem-format
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
		openssl_free_key($res);
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
		openssl_free_key($res);
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
        openssl_free_key($res);
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
                $rObj->type         = "EC";
                $rObj->curve		= $detail["ec"]["curve_name"];
                $rObj->publicKey    = \MTM\Encrypt\Factories::getEC()->getPublicKey($detail["key"]);
                
                //test x / y with: openssl ec -in key.pem -text -noout -conv_form uncompressed
                //src: https://stackoverflow.com/questions/29355027/what-method-does-openssl-use-to-combine-a-public-ec-keys-coordinates
                $rObj->{"public-x"}	= bin2hex($detail["ec"]["x"]);
                $rObj->{"public-y"}	= bin2hex($detail["ec"]["y"]);
                $rObj->{"private"}	= bin2hex($detail["ec"]["d"]);
                //d is private key
            } else {
                $rObj->type         = "UNKNOWN";
                $rObj->publicKey    = null;
            }
            
            return $rObj;
            
        } else {
            throw new \Exception("Failed to extract details for private key");
        }
	}
	public function createKeyPair($curve="secp256k1", $passPhrase=null)
	{
		$rObj			= new \stdClass();
		$rObj->private	= $this->createPrivateKey($curve, $passPhrase);
		$rObj->public	= $this->getPublicKeyFromPrivateKey($rObj->private);
		
		return $rObj;
	}
// 	public function getPEM($keyObj)
// 	{
// 		//return a PEM certificate 
// 		$tempKey	= \MHT\Factories::getFileSystems()->getSessionFile("key");
// 		$tempKey->setContent($keyObj->get());
		
// 		$tempPem	= \MHT\Factories::getFileSystems()->getSessionFile("pem");
// 		$cmdStr		= "openssl rsa -in '".$tempKey->getPathAsString()."' -out '".$tempPem->getPathAsString()."'";
		
// 		//need an interactive shell to fill in the details
// 		$shellObj	= \MHIT\Factories::getDevices()->getShell("shared");
		
// 		//need to deal with fail case
// 		if ($keyObj->getPassPhrase() === null) {
// 			//without a passphrase the shell exits without needing input
// 			$shellObj->exeCmd($cmdStr);
// 		} else {
// 			//enter passphrase
// 			$shellObj->exeCmd($cmdStr, $tempKey->getName() . ":");
// 			$shellObj->exeCmd($keyObj->getPassPhrase());
// 		}

// 		return \MTM\Encrypt\Factories::getRSA()->getPrivateKey(trim($tempPem->getContent()));
// 	}
	public function encrypt($keyObj, $strData, $pad=OPENSSL_PKCS1_PADDING)
	{
		$valid	= openssl_public_encrypt($strData, $encData, $keyObj->get(), $pad);
		if ($valid === true) {
			return $encData;
		} else {
			throw new \Exception("Failed to encrypt");
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
	    $res	= openssl_pkey_get_private($keyObj->get(), $keyObj->getPassPhrase());
	    if (is_resource($res) === true) {
	        return $res;
	    } else {
	        throw new \Exception("Failed to extract private key, maybe invalid pass phrase");
	    }
	}
}