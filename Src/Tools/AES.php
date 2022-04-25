<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Tools;

class AES
{
	public function getRandomString($len=40)
	{
		return \MTM\Utilities\Factories::getStrings()->getRandomByRegex($len);
	}
	public function getRandomBytes($len=40)
	{
		return openssl_random_pseudo_bytes($len);
	}
	public function encrypt($keyObj, $strData, $aad="", $iv=null, $opts=OPENSSL_RAW_DATA)
	{
		$ivLen		= openssl_cipher_iv_length($keyObj->getCipher());
		if ($iv === null) {
			if ($ivLen > 0) {
				$iv 		= $this->getRandomBytes($ivLen);
			} else {
				$iv 		= "";
			}
		}
		//silence the function or it will complain when the cipher does not support AEAD
		$encData	= @openssl_encrypt($strData, $keyObj->getCipher(), $keyObj->get(), $opts, $iv, $tag, $aad, 16);
		if ($encData !== false) {
			
			$rObj		= new \stdClass();
			$rObj->data	= $encData;
			$rObj->iv	= $iv;
			$rObj->tag	= $tag;
			$rObj->aad	= $aad;
			
			return $rObj;
			
		} else {
			throw new \Exception("Failed to encrypt input");
		}
	}
	public function decrypt($keyObj, $encData, $iv, $tag, $aad="", $opts=OPENSSL_RAW_DATA)
	{
		$decData		= openssl_decrypt($encData, $keyObj->getCipher(), $keyObj->get(), $opts, $iv, $tag, $aad);
		if ($decData !== false) {
			return $decData;
		} else {
			throw new \Exception("Failed to decrypt data");
		}
	}
}