## What is this?

Encryption in MTM using AES:

### Get a key:

#### GCM-256:

```
$keyObj	= \MTM\Encrypt\Factories::getAES()->getGcm256Key()->generateKey(40);
//OR if you want to use your own key
$key		= "My String Key";
$keyObj	= \MTM\Encrypt\Factories::getAES()->getGcm256Key($key);
```

## Encrypt:

```
$text		= "My secret message";
$encObj	= $keyObj->encrypt($text);

```

## Aad Encrypt (add additional random data for authentication):

```
$text		= "My secret message";
$aadLen	= 40;
$encObj	= $keyObj->aadEncrypt($text, $aadLen);

```

### bring your own Aad data

```
$text		= "My secret message";
$aad		= "some random data";
$encObj	= $keyObj->encrypt($text, $aad);

```

## Decrypt:

```
$data	= $keyObj->decrypt($encObj->data, $encObj->iv, $encObj->tag, $encObj->aad);
echo $data;

```