<?php
// Demo configuration with an intentionally dangerous setting (for Phase 3).

$config['base_url'] = 'http://localhost/booking';

// ISSUE: debug/display errors enabled in what is meant to be production config.
$config['display_errors'] = 1;

// ISSUE: database password committed to source control.
$db['default'] = array(
    'hostname' => 'localhost',
    'username' => 'root',
    'password' => 'P@ssw0rd123',
    'database' => 'booking',
    'dbdriver' => 'mysqli',
);
