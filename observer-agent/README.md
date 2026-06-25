# observer-agent (PHP)

A zero-dependency, single-file runtime error collector for PHP applications. It
captures **uncaught exceptions** and **fatal errors** as newline-delimited JSON
(JSONL), which the `observer` CLI ingests with `--runtime`.

It is designed to be safe in production: every code path fails silently and it
chains to any exception handler your application already registered, so it can
never break the host app.

## What it captures

For each failure: error **type**, **message**, **file**, **line**, **stack
trace**, request **URL** and **method**, **timestamp**, optional **user**, and
an optional **app** name.

## Install

Pick whichever fits your setup:

**1. php.ini (whole server / site) — recommended**
```ini
auto_prepend_file = /path/to/observer-agent/observer-agent.php
```

**2. Require it early in your front controller** (e.g. top of `index.php`)
```php
require __DIR__ . '/observer-agent/observer-agent.php';
```

The agent auto-installs on include. To install manually instead, set
`OBSERVER_AGENT_AUTOINSTALL=0` and call `ObserverAgent::install([...])` yourself.

## Configure

Via environment variables:

| Variable | Purpose | Default |
|---|---|---|
| `OBSERVER_RUNTIME_LOG` | Destination JSONL file | system temp dir / `observer-runtime.jsonl` |
| `OBSERVER_APP` | Application name stored with each event | _(none)_ |
| `OBSERVER_AGENT_AUTOINSTALL` | Set to `0` to disable auto-install | _(enabled)_ |

Or via `install()` options, including a `user_resolver` callback to attach the
current user id:

```php
ObserverAgent::install([
    'log_file'      => '/var/log/observer-runtime.jsonl',
    'app'           => 'booking-system',
    'user_resolver' => fn() => $_SESSION['user_id'] ?? null,
]);
```

> Choose a log path your web server user can write to, and rotate/clean it
> periodically (or ship it elsewhere). The agent only appends.

## Use the captured data

```bash
observer analyze /path/to/project --runtime /var/log/observer-runtime.jsonl
```

The report's **Runtime Errors** section groups repeated failures by signature
(type + file + line), most frequent first.

## Try it locally

```bash
OBSERVER_RUNTIME_LOG=/tmp/observer-runtime.jsonl OBSERVER_APP=demo \
  php examples/php-demo/runtime-demo.php db

observer analyze examples/php-demo --runtime /tmp/observer-runtime.jsonl
```
