package detector

import (
	"encoding/json"
	"strings"
)

// --- Frameworks & languages -------------------------------------------------

// composerManifest is the subset of composer.json we care about.
type composerManifest struct {
	Name    string            `json:"name"`
	Require map[string]string `json:"require"`
	Dev     map[string]string `json:"require-dev"`
}

// packageManifest is the subset of package.json we care about.
type packageManifest struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// phpFramework maps a Composer package prefix to a framework name.
var phpFrameworks = []struct{ pkg, name string }{
	{"laravel/framework", "Laravel"},
	{"codeigniter4/framework", "CodeIgniter 4"},
	{"codeigniter/framework", "CodeIgniter 3"},
	{"symfony/framework-bundle", "Symfony"},
	{"symfony/symfony", "Symfony"},
	{"slim/slim", "Slim"},
	{"cakephp/cakephp", "CakePHP"},
	{"yiisoft/yii2", "Yii 2"},
}

// nodeFrameworks maps an npm package to a framework name.
var nodeFrameworks = []struct{ pkg, name string }{
	{"@nestjs/core", "NestJS"},
	{"next", "Next.js"},
	{"nuxt", "Nuxt"},
	{"@angular/core", "Angular"},
	{"express", "Express"},
	{"koa", "Koa"},
	{"fastify", "Fastify"},
	{"@hapi/hapi", "Hapi"},
	{"react", "React"},
	{"vue", "Vue"},
}

func detectFrameworksAndLanguages(c *collected, ts *TechStack) {
	// PHP via composer.json
	if body, ok := c.read("composer.json"); ok {
		ts.addLanguage(Finding{Name: "PHP", Confidence: High, Evidence: []string{"composer.json present"}})
		var m composerManifest
		if json.Unmarshal([]byte(body), &m) == nil {
			deps := merge(m.Require, m.Dev)
			for _, fw := range phpFrameworks {
				if ver, ok := deps[fw.pkg]; ok {
					ts.addFramework(Finding{
						Name: fw.name, Version: cleanVersion(ver), Confidence: High,
						Evidence: []string{"composer.json requires " + fw.pkg + " " + cleanVersion(ver)},
					})
				}
			}
		}
	}
	// Laravel marker fallback.
	if _, ok := c.manifests["artisan"]; ok && !ts.hasFramework("Laravel") {
		ts.addFramework(Finding{Name: "Laravel", Confidence: High, Evidence: []string{"artisan console present"}})
	}
	// CodeIgniter 4 marker fallback.
	if _, ok := c.manifests["spark"]; ok && !ts.hasFramework("CodeIgniter 4") {
		ts.addFramework(Finding{Name: "CodeIgniter 4", Confidence: High, Evidence: []string{"spark CLI present"}})
	}
	// CodeIgniter vendored in system/ (no Composer entry). The core file defines
	// CI_VERSION; its major version distinguishes CI3 from CI4.
	if _, ok := c.manifests["CodeIgniter.php"]; ok &&
		!ts.hasFramework("CodeIgniter 3") && !ts.hasFramework("CodeIgniter 4") {
		body := readIf(c, "CodeIgniter.php")
		if strings.Contains(body, "CI_VERSION") {
			ts.addLanguage(Finding{Name: "PHP", Confidence: High, Evidence: []string{"CodeIgniter core present"}})
			ver := extractVersionNear(body, "CI_VERSION")
			name := "CodeIgniter"
			if strings.HasPrefix(ver, "4") {
				name = "CodeIgniter 4"
			} else if strings.HasPrefix(ver, "3") {
				name = "CodeIgniter 3"
			}
			ts.addFramework(Finding{
				Name: name, Version: ver, Confidence: High,
				Evidence: []string{"vendored CodeIgniter core (system/core/CodeIgniter.php)"},
			})
		}
	}

	// Node via package.json
	if body, ok := c.read("package.json"); ok {
		ts.addLanguage(Finding{Name: "JavaScript/TypeScript", Confidence: High, Evidence: []string{"package.json present"}})
		var m packageManifest
		if json.Unmarshal([]byte(body), &m) == nil {
			deps := merge(m.Dependencies, m.DevDependencies)
			for _, fw := range nodeFrameworks {
				if ver, ok := deps[fw.pkg]; ok {
					ts.addFramework(Finding{
						Name: fw.name, Version: cleanVersion(ver), Confidence: High,
						Evidence: []string{"package.json depends on " + fw.pkg + " " + cleanVersion(ver)},
					})
				}
			}
		}
	}

	// Python
	pyBody := firstNonEmpty(
		readIf(c, "requirements.txt"), readIf(c, "pyproject.toml"),
		readIf(c, "Pipfile"), readIf(c, "setup.py"),
	)
	if pyBody != "" || c.manifests["manage.py"] != "" {
		ts.addLanguage(Finding{Name: "Python", Confidence: High, Evidence: []string{"Python manifest present"}})
	}
	low := strings.ToLower(pyBody)
	if _, ok := c.manifests["manage.py"]; ok || strings.Contains(low, "django") {
		ev := "Django in dependencies"
		if _, ok := c.manifests["manage.py"]; ok {
			ev = "manage.py present"
		}
		ts.addFramework(Finding{Name: "Django", Confidence: High, Evidence: []string{ev}})
	}
	if strings.Contains(low, "fastapi") {
		ts.addFramework(Finding{Name: "FastAPI", Confidence: High, Evidence: []string{"fastapi in dependencies"}})
	}
	if strings.Contains(low, "flask") {
		ts.addFramework(Finding{Name: "Flask", Confidence: Medium, Evidence: []string{"flask in dependencies"}})
	}

	// Java
	javaBody := firstNonEmpty(readIf(c, "pom.xml"), readIf(c, "build.gradle"), readIf(c, "build.gradle.kts"))
	if javaBody != "" {
		ts.addLanguage(Finding{Name: "Java", Confidence: High, Evidence: []string{"Maven/Gradle build file present"}})
		if strings.Contains(javaBody, "spring-boot") || strings.Contains(javaBody, "org.springframework") {
			ts.addFramework(Finding{Name: "Spring", Confidence: High, Evidence: []string{"Spring dependency in build file"}})
		}
	}

	// Go
	if _, ok := c.manifests["go.mod"]; ok {
		ts.addLanguage(Finding{Name: "Go", Confidence: High, Evidence: []string{"go.mod present"}})
	}
}

// --- Databases --------------------------------------------------------------

func detectDatabases(c *collected, ts *TechStack) {
	// CodeIgniter database.php: 'dbdriver' => 'mysqli' / 'postgre' / etc.
	if body, ok := c.read("database.php"); ok {
		low := strings.ToLower(body)
		switch {
		case strings.Contains(low, "mysqli") || strings.Contains(low, "'mysql'"):
			ts.addDatabase(Finding{Name: "MySQL", Confidence: High, Evidence: []string{"dbdriver mysqli in database.php"}})
		case strings.Contains(low, "postgre"):
			ts.addDatabase(Finding{Name: "PostgreSQL", Confidence: High, Evidence: []string{"postgre driver in database.php"}})
		}
	}

	// .env DB_CONNECTION / DATABASE_URL hints.
	envBody := strings.ToLower(firstNonEmpty(readIf(c, ".env"), readIf(c, ".env.example")))
	if envBody != "" {
		if strings.Contains(envBody, "mysql") {
			ts.addDatabase(Finding{Name: "MySQL", Confidence: Medium, Evidence: []string{"mysql referenced in .env"}})
		}
		if strings.Contains(envBody, "pgsql") || strings.Contains(envBody, "postgres") {
			ts.addDatabase(Finding{Name: "PostgreSQL", Confidence: Medium, Evidence: []string{"postgres referenced in .env"}})
		}
		if strings.Contains(envBody, "mongodb") || strings.Contains(envBody, "mongo") {
			ts.addDatabase(Finding{Name: "MongoDB", Confidence: Medium, Evidence: []string{"mongo referenced in .env"}})
		}
	}

	// Dependency-based hints (PHP/Node/Python manifests).
	deps := strings.ToLower(firstNonEmpty(readIf(c, "composer.json"), "") +
		readIf(c, "package.json") + readIf(c, "requirements.txt") + readIf(c, "pyproject.toml"))
	if strings.Contains(deps, "mysqli") || strings.Contains(deps, "pdo_mysql") || strings.Contains(deps, "mysql2") {
		ts.addDatabase(Finding{Name: "MySQL", Confidence: Medium, Evidence: []string{"MySQL driver in dependencies"}})
	}
	if strings.Contains(deps, "psycopg") || strings.Contains(deps, "\"pg\"") || strings.Contains(deps, "pdo_pgsql") {
		ts.addDatabase(Finding{Name: "PostgreSQL", Confidence: Medium, Evidence: []string{"PostgreSQL driver in dependencies"}})
	}
	if strings.Contains(deps, "mongoose") || strings.Contains(deps, "pymongo") || strings.Contains(deps, "mongodb") {
		ts.addDatabase(Finding{Name: "MongoDB", Confidence: Medium, Evidence: []string{"MongoDB driver in dependencies"}})
	}

	// docker-compose service images.
	compose := strings.ToLower(firstNonEmpty(readIf(c, "docker-compose.yml"), readIf(c, "docker-compose.yaml")))
	if strings.Contains(compose, "image: mysql") || strings.Contains(compose, "image: mariadb") {
		ts.addDatabase(Finding{Name: "MySQL", Confidence: High, Evidence: []string{"MySQL/MariaDB service in docker-compose"}})
	}
	if strings.Contains(compose, "image: postgres") {
		ts.addDatabase(Finding{Name: "PostgreSQL", Confidence: High, Evidence: []string{"Postgres service in docker-compose"}})
	}
	if strings.Contains(compose, "image: mongo") {
		ts.addDatabase(Finding{Name: "MongoDB", Confidence: High, Evidence: []string{"Mongo service in docker-compose"}})
	}
}

// --- Infrastructure ---------------------------------------------------------

func detectInfrastructure(c *collected, ts *TechStack) {
	if _, ok := c.manifests["Dockerfile"]; ok {
		ts.addInfra(Finding{Name: "Docker", Confidence: High, Evidence: []string{"Dockerfile present"}})
	}
	if _, ok := c.manifests["docker-compose.yml"]; ok {
		ts.addInfra(Finding{Name: "Docker Compose", Confidence: High, Evidence: []string{"docker-compose.yml present"}})
	} else if _, ok := c.manifests["docker-compose.yaml"]; ok {
		ts.addInfra(Finding{Name: "Docker Compose", Confidence: High, Evidence: []string{"docker-compose.yaml present"}})
	}

	// Kubernetes: dedicated directory, or YAML manifests with apiVersion + kind.
	if c.dirs["k8s"] || c.dirs["kubernetes"] || c.dirs["manifests"] || c.dirs["charts"] {
		ts.addInfra(Finding{Name: "Kubernetes", Confidence: Medium, Evidence: []string{"kubernetes manifest directory present"}})
	} else {
		for _, p := range c.yamlFiles {
			body := readCapped(p, maxScanFileBytes)
			if strings.Contains(body, "apiVersion:") && strings.Contains(body, "kind:") &&
				(strings.Contains(body, "Deployment") || strings.Contains(body, "Service") || strings.Contains(body, "Pod")) {
				ts.addInfra(Finding{Name: "Kubernetes", Confidence: Medium, Evidence: []string{"Kubernetes manifest detected (" + baseName(p) + ")"}})
				break
			}
		}
	}

	// AWS indicators.
	awsEvidence := ""
	switch {
	case c.manifests["serverless.yml"] != "" || c.manifests["serverless.yaml"] != "":
		awsEvidence = "serverless framework config present"
	case c.dirs[".aws"] || c.dirs[".ebextensions"]:
		awsEvidence = "AWS config directory present"
	default:
		deps := strings.ToLower(readIf(c, "package.json") + readIf(c, "requirements.txt") + readIf(c, "pyproject.toml"))
		if strings.Contains(deps, "aws-sdk") || strings.Contains(deps, "boto3") || strings.Contains(deps, "@aws-sdk/") {
			awsEvidence = "AWS SDK in dependencies"
		} else {
			for _, p := range c.tfFiles {
				if strings.Contains(readCapped(p, maxScanFileBytes), "provider \"aws\"") {
					awsEvidence = "Terraform AWS provider (" + baseName(p) + ")"
					break
				}
			}
		}
	}
	if awsEvidence != "" {
		ts.addInfra(Finding{Name: "AWS", Confidence: Medium, Evidence: []string{awsEvidence}})
	}
}
