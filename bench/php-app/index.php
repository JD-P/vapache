<?php
header('Content-Type: application/json');
header('Cache-Control: no-store');
echo json_encode([
    'ok' => true,
    'runtime' => 'php-fpm',
    'path' => $_SERVER['REQUEST_URI'] ?? '',
]);
