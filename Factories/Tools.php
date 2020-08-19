<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Factories;

class Tools extends Base
{
	public function getRsa()
	{
		if (array_key_exists(__FUNCTION__, $this->_s) === false) {
			$this->_s[__FUNCTION__]	= new \MTM\Encrypt\Tools\RSA();
		}
		return $this->_s[__FUNCTION__];
	}
	public function getEc()
	{
		if (array_key_exists(__FUNCTION__, $this->_s) === false) {
			$this->_s[__FUNCTION__]	= new \MTM\Encrypt\Tools\EC();
		}
		return $this->_s[__FUNCTION__];
	}
	public function getAes()
	{
		if (array_key_exists(__FUNCTION__, $this->_s) === false) {
			$this->_s[__FUNCTION__]	= new \MTM\Encrypt\Tools\AES();
		}
		return $this->_s[__FUNCTION__];
	}
	public function getOpenSsl()
	{
		if (array_key_exists(__FUNCTION__, $this->_s) === false) {
			$this->_s[__FUNCTION__]	= new \MTM\Encrypt\Tools\OpenSSL();
		}
		return $this->_s[__FUNCTION__];
	}
}