## What is this?

Encryption in MTM


###AES-CBC-256 compat between PHP and MySQL

####MySQL (5.7 +):

```
SET @rawData					= "String I want to encrypt";
SET @salt						= "B5E2BDAE-F814-E9F6-3162-EA6D6FB437EC";
SET @keyStr					= "secretPassphrase";
	
SET block_encryption_mode 	= "aes-256-cbc";//use my.cnf to store so not having to set each time
SET @rawData					= TO_BASE64(@rawData);
SET @initVector				= RANDOM_BYTES(16);
SELECT TO_BASE64(AES_ENCRYPT(@rawData, SUBSTR(SHA2(CONCAT(@keyStr, @salt, @keyStr), 512), 1, 32), @initVector)) AS 'value', @keyStr AS "key", TO_BASE64(@initVector) AS 'iv';
```


####PHP:

```
$rawData			= "String I want to encrypt";
$salt				= "B5E2BDAE-F814-E9F6-3162-EA6D6FB437EC";
$keyStr			= "secretPassphrase";
	
$keyObj			= \MTM\Encrypt\Factories::getAES()->getCbc256Key(substr(hash("sha512", $keyStr.$salt.$keyStr), 0, 32));
$rObj				= $keyObj->encrypt($rawData);
echo base64_encode($rObj->data) . ", " . $keyObj->get() . ", " . base64_encode($rObj->iv);

```