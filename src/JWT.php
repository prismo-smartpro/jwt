<?php

namespace SmartPRO\Technology;

use Exception;

class JWT
{
    protected string $passwd;
    protected array $payload;
    protected int $exp;
    protected array $headers = [
        "alg" => "HS256",
        "typ" => "JWT"
    ];

    public function __construct($passwd, $exp = 3600)
    {
        $this->exp = $exp;
        $this->passwd = $passwd;
    }
    
    public function payload(array $payload): JWT
    {
        $payload['jti'] = $this->created_jti();
        $payload['iat'] = time();
        $payload['exp'] = time() + $this->exp;
        $this->payload = $payload;
        return $this;
    }

    /**
     * @throws Exception
     */
    public function verify($token)
    {
        $explode = explode(".", $token);
        if (count($explode) != 3) {
            throw new Exception("O token informado esta incompleto");
        }

        $headers = $explode[0];
        $payload = $explode[1];
        $signature = $explode[2];

        $verifySignature = $this->encrypt($headers . $payload);
        if ($signature != $verifySignature) {
            throw new Exception("A assinatura do token esta incorreta");
        }

        $payload = json_decode(base64_decode($payload));
        if ($payload->exp < time()) {
            throw new Exception("O token é valido, porém já venceu");
        }
        var_dump($this);
        return $payload;
    }

    public function encrypt($data): string
    {
        return base64_encode(hash_hmac("SHA256", $data, $this->passwd));
    }

    public function created(): string
    {
        $headers = base64_encode(json_encode($this->headers));
        $payload = base64_encode(json_encode($this->payload));
        $signature = $this->encrypt($headers . $payload);
        return "{$headers}.{$payload}.{$signature}";
    }

    /**
     * @throws Exception
     */
    private function created_jti()
    {
        $data = random_bytes(16);
        assert(strlen($data) == 16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * @param int $exp
     */
    public function setExp(int $exp): void
    {
        $this->exp = $exp;
    }
}