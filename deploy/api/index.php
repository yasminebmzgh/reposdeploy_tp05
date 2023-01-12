<?php
use Slim\Factory\AppFactory;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Tuupola\Middleware\JwtAuthentication as JwtAuthentication;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;


require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/models/Client.php';
require_once __DIR__ . '/models/Product.php';
require_once __DIR__ . '/../bootstrap.php';

const JWT_SECRET = "lala123";
// Create Slim AppFactory
$app = AppFactory::create();
// Add Middleware : JSON, Error, Headers
$app->addBodyParsingMiddleware();
$app->addErrorMiddleware(true, true, true);
$app->add(function(Request $request, RequestHandler $handler) {
	$response = $handler->handle($request);
	$response = $response->withAddedHeader('Content-Type', 'application/json');
	$response = $response->withAddedHeader('Access-Control-Allow-Origin', '*');
	$response = $response->withAddedHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
	$response = $response->withAddedHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
	return $response;
});
// Set Base Path
$app->setBasePath("/api");

$options = [
    "attribute" => "token",
    "header" => "Authorization",
    "regexp" => "/Bearer\s+(.*)$/i",
    "secure" => false,
    "algorithm" => ["HS256"],
    "secret" => JWT_SECRET,
    "path" => ["/api"],
    "ignore" => ["/api/login", "/api/hello", "/api/signup", "/api/client", "/api/product"],
    "error" => function ($response, $arguments) {
        $data = array('ERREUR' => 'Connexion', 'MESSAGE' => 'non-valid JWT');
        $response = $response->withStatus(401);
		$response->getBody()->write(json_encode($data));
        return $response;
    }
];
function createJwT (Response $response, int $payload) : string {

    $issuedAt = time();
    $expirationTime = $issuedAt +36000; // jwt valid for 10 hours from the issued time
	$payload = array(
		"iat" => $issuedAt,
		"exp" => $expirationTime,
		"data" => $payload
	);
	$token = JWT::encode($payload, JWT_SECRET, "HS256");
	return $token;
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
    "ignore" => ["/api/login", "/api/signup"],
    "error" => function ($response, $arguments) {
        $data = array('ERREUR' => 'Connexion', 'ERREUR' => 'JWT Non valide');
        $response = $response->withStatus(401);
        return $response->withHeader("Content-Type", "application/json")->getBody()->write(json_encode($data));
    }
]));

$app->get('/api/product/search/{name}', function (Request $request, Response $response, $args) {
    $json = file_get_contents("./mock/products.json");
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
$app->post('/login', function (Request $request, Response $response) {
	$login = $request->getParsedBody()['login'] ?? '';
	$password = $request->getParsedBody()['password'] ?? '';

	if (empty($login) || empty($password)|| !preg_match("/^[a-zA-Z0-9]+$/", $login) || !preg_match("/^[a-zA-Z0-9]+$/", $password)) {
		$response = $response->withStatus(401);
		$response->getBody()->write(json_encode(array('ERREUR' => 'Connexion', 'MESSAGE' => 'Incorrect or missing credentials')));
		return $response;
    }

	global $entityManager;
    $user = $entityManager->getRepository(Client::class)->findOneBy(array('login' => $login, 'password' => $password));

	if($user){
		$id = $user->getId();
		$token = createJwT($response, $id);
		$response->getBody()->write(json_encode(array('token' => $token)));
	} else {
		$response = $response->withStatus(401);
		$response->getBody()->write(json_encode(array('ERREUR' => 'Connexion', 'MESSAGE' => 'Unknown User')));
	}
	return $response;
});

$app->get('/clients', function (Request $request, Response $response) {
	global $entityManager;
	$clients = $entityManager->getRepository(Client::class)->findAll();
	$response->getBody()->write(json_encode($clients));
	return $response;
});

$app->get('/client', function (Request $request, Response $response) {
	$token_header = $request->getHeader("Authorization")[0];

	if(!preg_match('/Bearer\s(\S+)/', $token_header, $matches)) {
		$response = $response->withStatus(401);
		$response->getBody()->write("Invalid token");
		return $response;
	}
	$token = JWT::decode($matches[1], new Key(JWT_SECRET, "HS256"));
	$now = new DateTimeImmutable();
	if($token->exp < $now->getTimestamp()) {
		$response = $response->withStatus(401);
		$response->getBody()->write("Token expired");
		return $response;
	}
	global $entityManager;
	$client = $entityManager->getRepository(Client::class)->find($token->data);
	if ($client) {
		$response->getBody()->write(json_encode(json_encode($client)));
	} else {
		$response = $response->withStatus(401);
		$response->getBody()->write("Client not found");
	}
	return $response;
});

$app->post('/signup', function (Request $request, Response $response) {
	$body = $request->getParsedBody();
	$firstname = $body['firstname'] ?? "";
	$lastname = $body['lastname'] ?? "";
	$email = $body['email'] ?? "";
	$phone = $body['phone'] ?? "";
	$address = $body['address'] ?? "";
	$gender = $body['gender'] ?? "";
	$login = $body['login'] ?? "";
	$password = $body['password'] ?? "";

	if (empty($firstname) || empty($lastname) || empty($email) || empty($phone) || empty($address) || empty($gender) || empty($login) || empty($password) || !preg_match("/^[0-9]+$/", $phone) || !preg_match("/^[a-zA-Z0-9\s]+$/", $address) || !preg_match("/^[a-zA-Z0-9]+$/", $gender) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
		$response = $response->withStatus(401);
		$response->getBody()->write("Bad request");
		return $response;
	}

	global $entityManager;
	$client = new Client();
	$client->setFirstname($firstname);
	$client->setLastname($lastname);
	$client->setEmail($email);
	$client->setPhone($phone);
	$client->setGender($gender);
	$client->setAddress($address);
	$client->setLogin($login);
	$client->setPassword($password);
	$entityManager->persist($client);
	$entityManager->flush();
	$response->getBody()->write(json_encode($client));
	return $response;
});

$app->put('/client', function (Request $request, Response $response) {
	$body = $request->getParsedBody();
	$id = $body['id'] ?? "";

	if (empty($id) || !preg_match("/^[0-9]+$/", $id)) {
		$response = $response->withStatus(401);
		$response->getBody()->write("Missing id");
		return $response;
	}

	global $entityManager;
	$client = $entityManager->getRepository(Client::class)->find($id);
	if(!$client) {
		$response = $response->withStatus(401);
		$response->getBody()->write("Client not found");
		return $response;
	}
	$client = $body['firstname'] ? $client->setFirstname($body['firstname']) : $client;
	$client = $body['lastname'] ? $client->setLastname($body['lastname']) : $client;
	$client = $body['email'] ? $client->setEmail($body['email']) : $client;
	$client = $body['phone'] ? $client->setPhone($body['phone']) : $client;
	$client = $body['gender'] ? $client->setGender($body['gender']) : $client;
	$client = $body['address'] ? $client->setAddress($body['address']) : $client;
	$client = $body['login'] ? $client->setLogin($body['login']) : $client;
	$client = $body['password'] ? $client->setPassword($body['password']) : $client;
	$entityManager->persist($client);
	$entityManager->flush();
	$response->getBody()->write(json_encode($client));
	return $response;
});

$app->delete('/client', function (Request $request, Response $response) {
	$body = $request->getParsedBody();
	$id = $body['id'] ?? "";

	if (empty($id) || !preg_match("/^[0-9]+$/", $id)) {
		$response = $response->withStatus(401);
		$response->getBody()->write("Bad request");
		return $response;
	}

	global $entityManager;
	$client = $entityManager->getRepository(Client::class)->find($id);
	if(!$client) {
		$response = $response->withStatus(401);
		$response->getBody()->write("Client not found");
		return $response;
	}
	$entityManager->remove($client);
	$entityManager->flush();
	$response->getBody()->write("Client deleted");
	return $response;
});


// Run app
$app->add(new Tuupola\Middleware\JwtAuthentication($options));

$app->run();

?>