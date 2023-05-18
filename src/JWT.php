<?php

namespace SmartPRO\Technology;

use Exception;

class JWT
{
    protected ?string $password = null;

    public function create(array $payload = array(), $exp = (3600 * 24)): string
    {
        $payload["iss"] = $_SERVER["SERVER_NAME"];
        $payload["sub"] = "JWT Authentication Token";
        $payload["exp"] = time() + $exp;
        $payload["iat"] = time();
        $payload["jti"] = $this->uuid();
        $headers = $this->base64UrlEncode(json_encode([
            'alg' => 'HS256',
            'typ' => 'JWT'
        ]));
        $payload = $this->base64UrlEncode(json_encode($payload));
        $signature = $this->base64UrlEncode($this->hash("{$headers}.{$payload}"));
        return "{$headers}.{$payload}.{$signature}";
    }

    /**
     * @throws Exception
     */
    public function verify($token)
    {
        $token = explode(".", $token);
        if (count($token) !== 3) {
            throw new Exception("O token informado está incompleto!");
        }

        $headers = $token[0];
        $payload = $token[1];
        $signature = $token[2];

        if ($this->base64UrlEncode($this->hash("{$headers}.{$payload}")) != $signature) {
            throw new Exception("A senha do token está incorreta!");
        }

        $payload = json_decode($this->base64UrlDecode($payload));

        if (empty($payload)) {
            throw new Exception("Erro ao decodificar o token");
        }

        if ($payload->exp <= time()) {
            throw new Exception("O token não pode mais ser usado, ele já expirou!");
        }

        return $payload;
    }

    private function uuid(): string
    {
        if (function_exists('openssl_random_pseudo_bytes')) {
            $data = openssl_random_pseudo_bytes(16);
        } else {
            $data = uniqid('', true);
        }
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    private function base64UrlEncode($input): string
    {
        $base64 = base64_encode($input);
        $urlSafe = strtr($base64, '+/', '-_');
        return rtrim($urlSafe, '=');
    }

    private function base64UrlDecode($input)
    {
        $urlSafe = strtr($input, '-_', '+/');
        $base64 = str_pad($urlSafe, strlen($urlSafe) % 4, '=', STR_PAD_RIGHT);
        return base64_decode($base64);
    }

    private function hash($text): string
    {
        return hash_hmac("sha256", $text, $this->password);
    }

    public function setPassword(string $password): void
    {
        $this->password = $password;
    }
}