<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Models\RSA;

class PublicKey extends Base
{	
	public function encrypt($data, $pad=OPENSSL_PKCS1_PADDING)
	{
		return $this->getTool()->encrypt($this, $data, $pad);
	}
	public function validateSignature($strData, $signature, $algo=OPENSSL_ALGO_SHA1)
	{
		return $this->getTool()->verifySign($this, $strData, $signature, $algo);
	}
}