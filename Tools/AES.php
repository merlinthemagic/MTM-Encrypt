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
	public function encrypt($keyObj, $strData, $aad="")
	{
		$ivLen		= openssl_cipher_iv_length($keyObj->getCipher());
		$iv 		= $this->getRandomBytes($ivLen);
		$encData	= openssl_encrypt($strData, $keyObj->getCipher(), $keyObj->get(), OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
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
	public function decrypt($keyObj, $encData, $iv, $tag, $aad="")
	{
		$decData		= openssl_decrypt($encData, $keyObj->getCipher(), $keyObj->get(), OPENSSL_RAW_DATA, $iv, $tag, $aad);
		if ($decData !== false) {
			return $decData;
		} else {
			throw new \Exception("Failed to decrypt data");
		}
	}
}