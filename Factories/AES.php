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
	public function getCbc256Key($strKey=null)
	{
		$rObj	= new \MTM\Encrypt\Models\AES\CBC256();
		$rObj->setTool($this->getTool());
		if ($strKey !== null) {
			$rObj->set($strKey);
		}
		return $rObj;
	}
	public function getEcb128Key($strKey=null)
	{
		$rObj	= new \MTM\Encrypt\Models\AES\ECB128();
		$rObj->setTool($this->getTool());
		if ($strKey !== null) {
			$rObj->set($strKey);
		}
		return $rObj;
	}
	public function getTool()
	{
		return \MTM\Encrypt\Factories::getTools()->getAes();
	}
}