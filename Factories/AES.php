<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Factories;

class AES extends Base
{
	//use: $keyObj		= \MTM\Encrypt\Factories::getAES()->$METHOD();
	
	public function getGcm256Key($strKey=null)
	{
		$rObj	= new \MTM\Encrypt\Models\AES\GCM256();
		$rObj->setTool($this->getTool());
		if ($strKey !== null) {
			$rObj->set($strKey);
		}
		return $rObj;
	}
	public function getTool()
	{
		if (array_key_exists(__METHOD__, $this->_cStore) === false) {
			$this->_cStore[__METHOD__]	= new \MTM\Encrypt\Tools\AES();
		}
		return $this->_cStore[__METHOD__];
	}
}