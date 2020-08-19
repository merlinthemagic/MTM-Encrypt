<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Models\AES;

class ECB128 extends Base
{
	//Mysql AES_ENCRYPT() uses the full key, while php 128-ecb cuts the key to 16bytes (silent) n openssl_encrypt/decrypt
	
	public function __construct()
	{
		$this->_cipher	= "aes-128-ecb";
	}
	public function encrypt($data, $aad="")
	{
		return $this->getTool()->encrypt($this, $data, $aad);
	}
	public function aadEncrypt($data, $len=40)
	{
		//generate aad data for the user
		$aad	= $this->getTool()->getRandomBytes($len);
		return $this->encrypt($data, $aad);
	}
	public function decrypt($data, $iv=null, $tag=null, $aad="")
	{
		return $this->getTool()->decrypt($this, $data, $iv, $tag, $aad);
	}
}