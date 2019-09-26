<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Models\RSA;

class PrivateKey extends Base
{		
	private $_passPhrase=null;

	public function setPassPhrase($str)
	{
		$this->_passPhrase	= $str;
		return $this;
	}
	public function getPassPhrase()
	{
		return $this->_passPhrase;
	}
	public function getDecryptedKey()
	{
		return $this->getTool()->getDecryptedPrivateKey($this);
	}
	public function getEncryptedKey($newPassPhrase)
	{
	    return $this->getTool()->getEncryptedPrivateKey($this, $newPassPhrase);
	}
	public function getPublicKey()
	{
		return $this->getTool()->getPublicKeyFromPrivateKey($this);
	}
	public function getPublicSSHKey()
	{
	    return $this->getTool()->getPublicAsSSH($this);
	}
	public function decrypt($data)
	{
		return $this->getTool()->decrypt($this, $data);
	}
	public function sign($strData, $algo=OPENSSL_ALGO_SHA1)
	{
		return $this->getTool()->sign($this, $strData, $algo);
	}
}