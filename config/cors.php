<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Cross-Origin Resource Sharing (CORS) Configuration
    |--------------------------------------------------------------------------
    |
    | Here you may configure your settings for cross-origin resource sharing
    | or "CORS". This determines what cross-origin operations may execute
    | in web browsers. You are free to adjust these settings as needed.
    |
    | To learn more: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
    |
    */

    'paths' => ['*'],

    'allowed_methods' => ['*'],

    'allowed_origins' => [env('FRONTEND_URL', 'http://localhost:3000')],

    #'allowed_origins_patterns' => [],

    #'allowed_headers' => ['*'],

    #'exposed_headers' => [],

    #'max_age' => 0,

    #'supports_credentials' => true,



    'paths' => ['api/*'], // Rutas donde se aplicará CORS
    'allowed_methods' => ['*'], // Métodos HTTP permitidos
    'allowed_origins' => ['http://localhost:5173'], // Origen permitido
    'allowed_origins_patterns' => [],

    'allowed_origins_patterns' => ['/localhost:\d+/'], // Permite localhost con cualquier puerto

    'allowed_headers' => ['*'], // Headers permitidos
    'exposed_headers' => [],
    'max_age' => 0,
    'supports_credentials' => true, // Si la solicitud incluye credenciales (cookies, auth headers, etc.)







];
