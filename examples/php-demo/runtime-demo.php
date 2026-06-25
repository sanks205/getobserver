<?php
/**
 * Demo driver: trigger a runtime error so observer-agent captures it.
 *
 * Usage:
 *   OBSERVER_RUNTIME_LOG=/tmp/observer-runtime.jsonl \
 *   OBSERVER_APP=booking-system \
 *   php runtime-demo.php [db|payment|null]
 *
 * Each run produces one captured event. Run it a few times (different
 * scenarios) to simulate repeated production failures, then point the CLI at
 * the log file:  observer analyze . --runtime /tmp/observer-runtime.jsonl
 */

require __DIR__ . '/../../observer-agent/observer-agent.php';

$scenario = isset($argv[1]) ? $argv[1] : 'db';

switch ($scenario) {
    case 'db':
        throw new RuntimeException('SQLSTATE[HY000] [2002] Connection refused');
    case 'payment':
        throw new LogicException('Payment gateway timeout after 30s');
    case 'null':
        $booking = null;
        echo $booking->id; // read property on null -> fatal Error
        break;
    default:
        throw new Exception('Unknown demo scenario: ' . $scenario);
}
