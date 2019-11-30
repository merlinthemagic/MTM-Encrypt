<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt;

class Factories
{
	private static $_cStore=array();
	
	//USE: $aFact		= \MTM\Encrypt\Factories::$METHOD_NAME();
	
	public static function getTools()
	{
		if (array_key_exists(__FUNCTION__, self::$_cStore) === false) {
			self::$_cStore[__FUNCTION__]	= new \MTM\Encrypt\Factories\Tools();
		}
		return self::$_cStore[__FUNCTION__];
	}
	public static function getRSA()
	{
		if (array_key_exists(__FUNCTION__, self::$_cStore) === false) {
			self::$_cStore[__FUNCTION__]	= new \MTM\Encrypt\Factories\RSA();
		}
		return self::$_cStore[__FUNCTION__];
	}
	public static function getAES()
	{
		if (array_key_exists(__FUNCTION__, self::$_cStore) === false) {
			self::$_cStore[__FUNCTION__]	= new \MTM\Encrypt\Factories\AES();
		}
		return self::$_cStore[__FUNCTION__];
	}
}