<?php
// Demo CodeIgniter database configuration.

$active_group = 'default';
$query_builder = TRUE;

$db['default'] = array(
    'dsn'      => '',
    'hostname' => 'localhost',
    'username' => 'root',
    // ISSUE: hardcoded production-looking password committed to source.
    'password' => 'P@ssw0rd123',
    'database' => 'booking',
    'dbdriver' => 'mysqli',
    'pconnect' => FALSE,
    'db_debug' => TRUE,
);
