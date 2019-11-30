<?php
//© 2019 Martin Peter Madsen
namespace MTM\Encrypt\Tools;

class OpenSSL
{
	public function getRSA()
	{
		$segs		= array();
		$segs[]		= $this->getHeadMinimal();
		$segs[]		= $this->getNewOids();
		$segs[]		= $this->getTsaDefault();
		$segs[]		= $this->getTsa1();

		return $this->stitchSegments($segs);
	}
	private function getHeadMinimal()
	{	
		$lines											= array();
		$lines[]	= "HOME								= .";
		$lines[]	= "RANDFILE							= \$ENV::HOME/.rnd";
		$lines[]	= "oid_section						= new_oids";

		return $lines;
	}
	private function getNewOids()
	{
		$lines											= array();
		$lines[]	= "[ new_oids ]";
		$lines[]	= "tsa_policy1						= 1.2.3.4.1";
		$lines[]	= "tsa_policy2						= 1.2.3.4.5.6";
		$lines[]	= "tsa_policy3						= 1.2.3.4.5.7";

		return $lines;
	}
	private function getTsaDefault()
	{
		$lines											= array();
		$lines[]	= "[ tsa ]";
		$lines[]	= "default_tsa						= tsa_config1";
		
		return $lines;
	}
	private function getTsa1()
	{
		//ca - default config
		$lines											= array();
		$lines[]	= "[ tsa_config1 ]";
		$lines[]	= "dir								= ./demoCA";
		$lines[]	= "serial							= \$dir/tsaserial";
		$lines[]	= "crypto_device					= builtin";
		$lines[]	= "signer_cert						= \$dir/tsacert.pem";
		$lines[]	= "certs							= \$dir/cacert.pem";
		$lines[]	= "signer_key						= \$dir/private/tsakey.pem";
		$lines[]	= "default_policy					= tsa_policy1";
		$lines[]	= "other_policies					= tsa_policy2, tsa_policy3";
		$lines[]	= "digests							= sha1, sha256, sha384, sha512";
		$lines[]	= "accuracy							= secs:1, millisecs:500, microsecs:100";
		$lines[]	= "clock_precision_digits			= 0";
		$lines[]	= "ordering							= yes";
		$lines[]	= "tsa_name							= yes";
		$lines[]	= "ess_cert_id_chain				= no";
		
		return $lines;
	}
	private function stitchSegments($segs=array())
	{
		$lines	= array();
		foreach ($segs as $seg) {
			$lines		= array_merge($lines, $seg);
			$lines[]	= "";
		}
		return $lines;
	}
}