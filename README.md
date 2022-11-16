# INSTALAÇÃO
```bash
composer require prismo-smartpro/jwt
```

# COMO USAR

```php
<?php
require "vendor/autoload.php";

/*
 * INICIA A CLASSE DO TOKEN
 */
$jwt = new \SmartPRO\Technology\JWT('123456');
$jwt->setExp(3600);
/*
 * CRIAR UM TOKEN A PARTIR DO PAYLOAD INFORMADO
 */
$token = $jwt->payload([
    "userId" => 165895
])->created();
/*
 * VERIFICA SE UM TOKEN INFORMADO É VÁLIDO
 */
try {
    $data = $jwt->verify('token');
} catch (Exception $e) {
    // Continue...
}
```