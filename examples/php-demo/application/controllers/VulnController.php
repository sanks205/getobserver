<?php
// Demo controller with intentional OWASP-class vulnerabilities (Theme 1 rules).

class VulnController extends CI_Controller
{
    public function show()
    {
        // ISSUE: reflected XSS — request value echoed without escaping.
        echo $_GET['name'];

        // ISSUE: path traversal / LFI — user input in an include.
        include $_GET['page'];

        // ISSUE: insecure deserialization of attacker-controlled input.
        $data = unserialize($_POST['payload']);

        // ISSUE: SSRF — request target built from user input.
        $ch = curl_init($_GET['url']);

        // ISSUE: TLS verification disabled — enables man-in-the-middle.
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

        return $data;
    }
}
