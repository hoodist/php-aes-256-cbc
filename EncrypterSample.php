<?php

class EncrypterSample {
    private static $supportedCiphers = [
        'aes-128-cbc' => ['size' => 16, 'aead' => false],
        'aes-256-cbc' => ['size' => 32, 'aead' => false],
        'aes-128-gcm' => ['size' => 16, 'aead' => true],
        'aes-256-gcm' => ['size' => 32, 'aead' => true],
    ];
    private string $cipher = 'aes-128-cbc';
    private string $key = '123456789-123456789-123456789-12';

    public function encrypt($value, $serialize = false)
    {
        $iv = random_bytes(openssl_cipher_iv_length(strtolower($this->cipher)));

        $tag = '';

        $value = self::$supportedCiphers[strtolower($this->cipher)]['aead']
            ? \openssl_encrypt(
                $serialize ? serialize($value) : $value,
                strtolower($this->cipher), $this->key, 0, $iv, $tag
            )
            : \openssl_encrypt(
                $serialize ? serialize($value) : $value,
                strtolower($this->cipher), $this->key, 0, $iv
            );

        if ($value === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        $iv = base64_encode($iv);
        $tag = base64_encode($tag);

        $mac = self::$supportedCiphers[strtolower($this->cipher)]['aead']
            ? ''
            : $this->hash($iv, $value);

        $json = json_encode(compact('iv', 'value', 'mac', 'tag'), JSON_UNESCAPED_SLASHES);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptException('Could not encrypt the data.');
        }

        return base64_encode($json);
    }

    public function decrypt($payload, $unserialize = false)
    {
        $payload = $this->getJsonPayload($payload);

        $iv = base64_decode($payload['iv']);

        $this->ensureTagIsValid(
            $tag = empty($payload['tag']) ? null : base64_decode($payload['tag'])
        );

        $decrypted = \openssl_decrypt(
            $payload['value'], strtolower($this->cipher), $this->key, 0, $iv, $tag ?? ''
        );

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    protected function hash($iv, $value)
    {
        return hash_hmac('sha256', $iv.$value, $this->key);
    }

    protected function getJsonPayload($payload)
    {
        $payload = json_decode(base64_decode($payload), true);

        if (! $this->validPayload($payload)) {
            throw new DecryptException('The payload is invalid.');
        }

        if (! self::$supportedCiphers[strtolower($this->cipher)]['aead'] && ! $this->validMac($payload)) {
            throw new DecryptException('The MAC is invalid.');
        }

        return $payload;
    }

    protected function validPayload($payload)
    {
        return is_array($payload) && isset($payload['iv'], $payload['value'], $payload['mac']) &&
            strlen(base64_decode($payload['iv'], true)) === openssl_cipher_iv_length(strtolower($this->cipher));
    }

    protected function validMac(array $payload)
    {
        return hash_equals(
            $this->hash($payload['iv'], $payload['value']), $payload['mac']
        );
    }

    protected function ensureTagIsValid($tag)
    {
        if (self::$supportedCiphers[strtolower($this->cipher)]['aead'] && strlen($tag) !== 16) {
            throw new DecryptException('Could not decrypt the data.');
        }

        if (! self::$supportedCiphers[strtolower($this->cipher)]['aead'] && is_string($tag)) {
            throw new DecryptException('Unable to use tag because the cipher algorithm does not support AEAD.');
        }
    }
}
