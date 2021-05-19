<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Models\AES;

class CBC256 extends Base
{
	//Mysql AES_ENCRYPT() cuts the key into 16byte chunks and xors them chained.
	//Easiest way to keep php and MYSQL cmpat is to use 16 byte (32 hex char) keys in PHP with OPENSSL_RAW_DATA padding and a 16 byte IV
	
	public function __construct()
	{
		$this->_cipher	= "aes-256-cbc";
	}
	public function encrypt($data, $aad="", $iv=null, $opts=OPENSSL_RAW_DATA)
	{
		return $this->getTool()->encrypt($this, $data, $aad, $iv, $opts);
	}
	public function aadEncrypt($data, $len=40)
	{
		//generate aad data for the user
		$aad	= $this->getTool()->getRandomBytes($len);
		return $this->encrypt($data, $aad);
	}
	public function decrypt($data, $iv, $tag="", $aad="", $opts=OPENSSL_RAW_DATA)
	{
		return $this->getTool()->decrypt($this, $data, $iv, $tag, $aad, $opts);
	}
}