<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Models\AES;

class Base
{		
	protected $_strKey=null;
	protected $_toolObj=null;
	protected $_cipher=null;
	
	public function set($str)
	{
		$this->_strKey	= $str;
		return $this;
	}
	public function get()
	{
		return $this->_strKey;
	}
	public function getCipher()
	{
		return $this->_cipher;
	}
	public function generateKey($len=40)
	{
		//generate a random string key
		$this->set($this->getTool()->getRandomString($len));
		return $this;
	}
	public function setTool($toolObj)
	{
		$this->_toolObj	= $toolObj;
		return $this;
	}
	public function getTool()
	{
		return $this->_toolObj;
	}
}