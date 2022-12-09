<?php
use Slim\Factory\AppFactory;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Tuupola\Middleware\JwtAuthentication as JwtAuthentication;
use Firebase\JWT\JWT;

require '../vendor/autoload.php';

const JWT_SECRET = "";

$app = AppFactory::create();

function createJWT($response, $login) {
    $issuedAt = time();
    $expirationTime = $issuedAt + 600;
    $payload = array(
      'login' => $login,
      'iat' => $issuedAt,
      'exp' => $expirationTime
    );
  
    $token_jwt = JWT::encode($payload, JWT_SECRET, "HS256");
    $response = $response->withHeader("Authorization", "Bearer {$token_jwt}");
    return $response;
}

// Config authenticator Tuupola
$app->add(new JwtAuthentication([
    "secret" => JWT_SECRET,
    "attribute" => "token",
    "header" => "Authorization",
    "regexp" => "/Bearer\s+(.*)$/i",
    "secure" => false,
    "algorithm" => ["HS256"],

    "path" => ["/api"],
    "ignore" => ["/api/login"],
    "error" => function ($response, $arguments) {
        $data = array('ERREUR' => 'Connexion', 'ERREUR' => 'JWT Non valide');
        $response = $response->withStatus(401);
        return $response->withHeader("Content-Type", "application/json")->getBody()->write(json_encode($data));
    }
]));

$app->get('/api/product/search/{name}', function (Request $request, Response $response, $args) {
    $json = file_get_contents("./mock/bouchon.json");
    $array = json_decode($json, true);
    $name = $args ['name'];
    $array = array_filter($array, function($item) use ($name) {
        if (stripos($item['name'], $name) !== false) {
            return true;
        }
    });
    $response->getBody()->write(json_encode ($array));
    return $response;
});


$app->get('/api/auth/{login}', function (Request $request, Response $response, $args) {
    $login = $args['login'];
    if ($login) 
    {
        $data["login"] = $login;
        $response = addHeaders($response);
        $response = createJWT($response, $login);
        $response->getBody()->write(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    }
    else {
        $response = $response->withStatus(401);
    }
    
    return $response;
});

$app->post('/api/login', function (Request $request, Response $response, $args) {
    $body = $request->getParsedBody();
    $login = $body['login'] ?? "";
    $mdp = $body['password'] ?? "";

    $error = (!(preg_match("/[a-zA-Z0-9]{1,20}/", $login)) || !(preg_match("/[a-zA-Z0-9]{1,20}/", $mdp)));

    if(!$error)
    {
        $data["login"] = $login;
        $response = addHeaders($response);
        $response = createJWT($response, $login);
        $response->getBody()->write(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    }
    else {
        $response = $response->withStatus(401);
    }

    return $response;
});

// Run app
$app->run();

?>