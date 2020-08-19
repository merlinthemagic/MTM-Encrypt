<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Models\AES;

class CBC256 extends Base
{
	public function __construct()
	{
		$this->_cipher	= "aes-256-cbc";
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
	public function decrypt($data, $iv, $tag, $aad="")
	{
		return $this->getTool()->decrypt($this, $data, $iv, $tag, $aad);
	}
}