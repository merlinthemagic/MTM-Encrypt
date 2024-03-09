<?php
//� 2023 Martin Peter Madsen
namespace MTM\Encrypt\Models\RSA;

class PublicSshKey extends Base
{	
	public function encrypt($data, $pad=OPENSSL_PKCS1_PADDING)
	{
		return $this->getTool()->encrypt($this, $data, $pad);
	}
}