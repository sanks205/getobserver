<?php
/**
 * Observer Agent — lightweight runtime error collector for PHP applications.
 *
 * Part of the AI Production Debugging Assistant (Phase 4). It captures uncaught
 * exceptions and fatal errors as newline-delimited JSON (JSONL), which the
 * `observer` CLI ingests via `--runtime`.
 *
 * Design goals:
 *   - Zero dependencies, single file, drop-in.
 *   - Must NEVER break the host application: every path fails silently.
 *   - Polite: chains to any exception handler the app already registered.
 *
 * Install (pick one):
 *   1) Add to php.ini:      auto_prepend_file = /path/to/observer-agent.php
 *   2) Require it early:    require __DIR__.'/observer-agent.php';  // top of index.php
 *
 * Configure (optional) via environment variables or install() options:
 *   OBSERVER_RUNTIME_LOG   destination JSONL file (default: temp dir)
 *   OBSERVER_APP           application name recorded with each event
 *   OBSERVER_AGENT_AUTOINSTALL=0   disable auto-install (call install() yourself)
 */

if (!class_exists('ObserverAgent')) {

final class ObserverAgent
{
    /** @var string */ private static $logFile;
    /** @var string|null */ private static $appName;
    /** @var callable|null */ private static $userResolver;
    /** @var bool */ private static $captureWarnings = false;
    /** @var bool */ private static $installed = false;
    /** @var callable|null */ private static $prevExceptionHandler = null;

    /**
     * Register the agent's handlers.
     *
     * @param array $opts log_file, app, user_resolver (callable), capture_warnings (bool)
     */
    public static function install(array $opts = [])
    {
        if (self::$installed) {
            return;
        }

        $log = isset($opts['log_file']) ? $opts['log_file'] : getenv('OBSERVER_RUNTIME_LOG');
        if (!$log) {
            $log = rtrim(sys_get_temp_dir(), "/\\") . DIRECTORY_SEPARATOR . 'observer-runtime.jsonl';
        }
        self::$logFile = $log;

        self::$appName = isset($opts['app']) ? $opts['app'] : (getenv('OBSERVER_APP') ?: null);
        self::$userResolver = isset($opts['user_resolver']) ? $opts['user_resolver'] : null;
        self::$captureWarnings = !empty($opts['capture_warnings']);

        self::$prevExceptionHandler = set_exception_handler(['ObserverAgent', 'handleException']);
        set_error_handler(['ObserverAgent', 'handleError']);
        register_shutdown_function(['ObserverAgent', 'handleShutdown']);

        self::$installed = true;
    }

    /** Handle an uncaught exception, then defer to the app's previous handler. */
    public static function handleException($e)
    {
        self::record([
            'type'     => get_class($e),
            'message'  => $e->getMessage(),
            'file'     => $e->getFile(),
            'line'     => $e->getLine(),
            'trace'    => $e->getTraceAsString(),
            'severity' => 'error',
        ]);

        if (self::$prevExceptionHandler) {
            call_user_func(self::$prevExceptionHandler, $e);
        }
    }

    /** Capture fatal errors (and warnings if enabled); never suppress PHP's own handling. */
    public static function handleError($errno, $errstr, $errfile, $errline)
    {
        $fatalMask = E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR;
        $isFatal = ($errno & $fatalMask) !== 0;

        if ($isFatal || self::$captureWarnings) {
            self::record([
                'type'     => self::errName($errno),
                'message'  => $errstr,
                'file'     => $errfile,
                'line'     => $errline,
                'trace'    => '',
                'severity' => $isFatal ? 'fatal' : 'warning',
            ]);
        }

        return false; // let PHP's normal error handling continue
    }

    /** Capture fatal errors that bypass the error handler (e.g. out-of-memory). */
    public static function handleShutdown()
    {
        $err = error_get_last();
        if ($err && ($err['type'] & (E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR)) !== 0) {
            self::record([
                'type'     => self::errName($err['type']),
                'message'  => $err['message'],
                'file'     => $err['file'],
                'line'     => $err['line'],
                'trace'    => '',
                'severity' => 'fatal',
            ]);
        }
    }

    /** Serialize one event as a JSON line and append it under an exclusive lock. */
    private static function record(array $event)
    {
        try {
            $event['timestamp'] = date('c');
            $event['url']    = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI']
                             : (isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : 'cli');
            $event['method'] = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'CLI';
            if (self::$appName) {
                $event['app'] = self::$appName;
            }
            $user = self::resolveUser();
            if ($user !== null) {
                $event['user'] = (string) $user;
            }

            $line = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if ($line === false) {
                return;
            }

            $fh = @fopen(self::$logFile, 'a');
            if ($fh) {
                @flock($fh, LOCK_EX);
                @fwrite($fh, $line . "\n");
                @flock($fh, LOCK_UN);
                @fclose($fh);
            }
        } catch (\Throwable $t) {
            // The agent must never throw into the host application.
        }
    }

    private static function resolveUser()
    {
        try {
            if (is_callable(self::$userResolver)) {
                return call_user_func(self::$userResolver);
            }
        } catch (\Throwable $t) {
        }
        return null;
    }

    private static function errName($errno)
    {
        $map = [
            E_ERROR => 'E_ERROR', E_WARNING => 'E_WARNING', E_PARSE => 'E_PARSE',
            E_NOTICE => 'E_NOTICE', E_USER_ERROR => 'E_USER_ERROR',
            E_USER_WARNING => 'E_USER_WARNING', E_USER_NOTICE => 'E_USER_NOTICE',
            E_CORE_ERROR => 'E_CORE_ERROR', E_COMPILE_ERROR => 'E_COMPILE_ERROR',
            E_DEPRECATED => 'E_DEPRECATED',
        ];
        return isset($map[$errno]) ? $map[$errno] : ('E_' . $errno);
    }
}

// Auto-install on include unless explicitly disabled.
if (getenv('OBSERVER_AGENT_AUTOINSTALL') !== '0') {
    ObserverAgent::install();
}

}
