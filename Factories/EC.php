<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Factories;

class EC extends Base
{
	//use: $keyObj		= \MTM\Encrypt\Factories::getEC()->$METHOD();
	
	public function getPrivateKey($strKey=null, $passPhrase=null)
	{
		$rObj	= new \MTM\Encrypt\Models\EC\PrivateKey($this->getTool(), $strKey, $passPhrase);
		return $rObj;
	}
	public function getPublicKey($strKey=null)
	{
		$rObj	= new \MTM\Encrypt\Models\EC\PublicKey();
		$rObj->setTool($this->getTool());
		
		if ($strKey !== null) {
			$rObj->set($strKey);
		}
		return $rObj;
	}
	public function getPublicSshKey($strKey=null)
	{
		$rObj	= new \MTM\Encrypt\Models\EC\PublicSshKey();
		$rObj->setTool($this->getTool());
		
		if ($strKey !== null) {
			$rObj->set($strKey);
		}
		return $rObj;
	}
	public function getTool()
	{
		return \MTM\Encrypt\Factories::getTools()->getEc();
	}
}