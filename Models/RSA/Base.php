<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Models\RSA;

class Base
{		
	protected $_strKey=null;
	protected $_toolObj=null;

	public function set($str)
	{
		//get rid of the differnet variations of line breaks so data
		//does not depend on the platform and can be compared as strings
		$str			= str_replace(array("\r\n", "\n\r", "\r"), "\n", $str);
		$this->_strKey	= trim($str);
		return $this;
	}
	public function get()
	{
		return $this->_strKey;
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