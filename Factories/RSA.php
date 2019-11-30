<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Factories;

class RSA extends Base
{
	//use: $keyObj		= \MTM\Encrypt\Factories::getRSA()->$METHOD();
	
	public function getPrivateKey($strKey=null, $passPhrase=null)
	{
		$rObj	= new \MTM\Encrypt\Models\RSA\PrivateKey();
		$rObj->setTool($this->getTool());
		if ($strKey !== null) {
			$rObj->set($strKey);
		}
		if ($passPhrase !== null) {
			$rObj->setPassPhrase($passPhrase);
		}
		return $rObj;
	}
	public function getPublicKey($strKey=null)
	{
		$rObj	= new \MTM\Encrypt\Models\RSA\PublicKey();
		$rObj->setTool($this->getTool());
		
		if ($strKey !== null) {
			$rObj->set($strKey);
		}
		return $rObj;
	}
	public function getPublicSshKey($strKey=null)
	{
		$rObj	= new \MTM\Encrypt\Models\RSA\PublicSshKey();
		$rObj->setTool($this->getTool());
		
		if ($strKey !== null) {
			$rObj->set($strKey);
		}
		return $rObj;
	}
	public function getTool()
	{
		return \MTM\Encrypt\Factories::getTools()->getRsa();
	}
}