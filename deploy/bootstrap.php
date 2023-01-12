<?php

require_once __DIR__ . '/vendor/autoload.php';

use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;

date_default_timezone_set('America/Lima');

$isDevMode = true;
$config = Setup::createYAMLMetadataConfiguration(array(__DIR__."/config/yaml"), $isDevMode);
$conn = array(
	'host' => 'dpg-cf00fhqrrk0eqcopot2g-a.oregon-postgres.render.com',
	'driver' => 'pdo_pgsql',
	'user' => 'yasmine_db_user',
	'password' => 'AJVxIVgIBYxWnGWYyumJcawZSrE6WoUa',
	'dbname' => 'yasmine_db',
	'port' => '5432'
);

$entityManager = EntityManager::create($conn, $config);

