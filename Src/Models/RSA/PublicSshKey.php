<?php
//© 2017 Martin Madsen
namespace MTO\Data\Encryption\Keys;

class PublicSshKey extends Base
{	
	public function encrypt($data, $pad=OPENSSL_PKCS1_PADDING)
	{
		return $this->getTool()->encrypt($this, $data, $pad);
	}
}