"""
Subdomain Wordlists
Enhanced wordlists for security-focused subdomain discovery
"""

# Basic wordlist (adapted from CloudSight's COMMON_SUBDOMAINS)
BASIC_WORDLIST = [
    "www", "api", "app", "my", "shop", "mail", "dev", "staging",
    "prod", "blog", "support", "help", "status", "docs", "developer",
    "admin", "portal", "login", "signin", "assets", "cdn", "images",
    "static", "cloud"
]

# Common web subdomains (extended)
COMMON_WORDLIST = BASIC_WORDLIST + [
    "test", "demo", "beta", "alpha", "preview", "temp", "backup",
    "old", "new", "m", "mobile", "secure", "ssl", "vpn", "ftp",
    "sftp", "ssh", "remote", "access", "gateway", "proxy", "lb",
    "loadbalancer", "cdn", "media", "video", "audio", "download",
    "upload", "files", "documents", "resources", "content", "cms",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "search", "solr", "kibana", "grafana", "prometheus", "monitoring",
    "metrics", "logs", "sentry", "bugtracker", "issues", "tickets",
    "crm", "erp", "hr", "finance", "accounting", "billing", "payments",
    "checkout", "cart", "store", "shop", "ecommerce", "marketplace",
    "forum", "community", "social", "chat", "messenger", "slack",
    "discord", "telegram", "whatsapp", "email", "smtp", "imap", "pop3",
    "calendar", "contacts", "drive", "storage", "backup", "archive",
    "wiki", "knowledge", "kb", "faq", "tutorials", "guides", "learn",
    "training", "courses", "webinar", "events", "news", "press",
    "career", "jobs", "recruitment", "hire", "team", "about", "contact"
]

# Security-focused wordlist for bug bounty and penetration testing
SECURITY_WORDLIST = COMMON_WORDLIST + [
    # Admin and management interfaces
    "admin", "administrator", "manage", "management", "console", "dashboard",
    "control", "panel", "cpanel", "webmail", "phpmyadmin", "adminer",
    "pgadmin", "grafana", "kibana", "jenkins", "bamboo", "travis",
    "circleci", "gitlab", "github", "bitbucket", "jira", "confluence",
    
    # Development and testing
    "dev", "develop", "development", "test", "testing", "qa", "quality",
    "stage", "staging", "prod", "production", "build", "ci", "cd",
    "deploy", "deployment", "release", "beta", "alpha", "canary",
    "experimental", "lab", "sandbox", "playground", "demo", "prototype",
    
    # Infrastructure and services
    "api", "gateway", "proxy", "load", "loadbalancer", "lb", "balancer",
    "firewall", "waf", "cdn", "cache", "redis", "memcache", "elastic",
    "elasticsearch", "kibana", "logstash", "splunk", "datadog", "newrelic",
    "monitoring", "metrics", "health", "status", "heartbeat", "ping",
    
    # Databases and storage
    "db", "database", "mysql", "postgres", "postgresql", "oracle", "mssql",
    "mongo", "mongodb", "cassandra", "dynamodb", "couchdb", "influx",
    "backup", "restore", "archive", "storage", "s3", "blob", "files",
    
    # Security services
    "auth", "authentication", "sso", "saml", "oauth", "oidc", "ldap",
    "ad", "identity", "iam", "rbac", "acl", "vault", "secrets", "keys",
    "cert", "certificate", "ssl", "tls", "ca", "pki", "crypto",
    
    # Communication services
    "mail", "email", "smtp", "imap", "pop3", "exchange", "outlook",
    "postfix", "sendmail", "chat", "messaging", "slack", "teams",
    "zoom", "webex", "meet", "hangouts", "discord", "telegram",
    
    # Common vulnerabilities and misconfigurations
    "backup", "bak", "old", "new", "tmp", "temp", "test", "debug",
    "trace", "log", "logs", "error", "errors", "exception", "dump",
    "core", "config", "configuration", "settings", "env", "environment",
    "secret", "private", "internal", "hidden", "shadow", "ghost",
    
    # Cloud and container services
    "aws", "azure", "gcp", "cloud", "k8s", "kubernetes", "docker",
    "container", "pod", "service", "ingress", "istio", "consul",
    "vault", "nomad", "terraform", "ansible", "puppet", "chef",
    
    # Monitoring and observability
    "prometheus", "grafana", "jaeger", "zipkin", "tracing", "apm",
    "sentry", "bugsnag", "rollbar", "honeybadger", "airbrake", "raygun",
    "pingdom", "uptimerobot", "newrelic", "datadog", "dynatrace",
    
    # Network and infrastructure
    "vpn", "firewall", "router", "switch", "gateway", "proxy", "cache",
    "cdn", "edge", "node", "cluster", "master", "slave", "replica",
    "primary", "secondary", "standby", "failover", "disaster", "recovery",
    
    # Web servers and applications
    "apache", "nginx", "iis", "tomcat", "jetty", "undertow", "weblogic",
    "websphere", "jboss", "wildfly", "glassfish", "liberty", "payara",
    
    # Version control and CI/CD
    "git", "svn", "mercurial", "bazaar", "perforce", "tfs", "vsts",
    "jenkins", "bamboo", "teamcity", "travis", "circleci", "gitlab",
    "github", "bitbucket", "codecommit", "azure-devops", "drone",
    
    # Content management and e-commerce
    "wordpress", "drupal", "joomla", "magento", "shopify", "woocommerce",
    "prestashop", "opencart", "oscommerce", "zencart", "ubercart",
    
    # Security tools and scanners
    "nessus", "openvas", "qualys", "rapid7", "nexpose", "acunetix",
    "appscan", "checkmarx", "veracode", "sonarqube", "fortify", "snyk",
    
    # Common IoT and embedded devices
    "iot", "sensor", "camera", "webcam", "printer", "scanner", "router",
    "modem", "switch", "ap", "wireless", "wifi", "bluetooth", "zigbee",
    
    # Regional and language variants
    "en", "us", "uk", "eu", "asia", "apac", "latam", "emea", "int",
    "international", "global", "local", "regional", "country", "lang",
    "locale", "i18n", "l10n", "translation", "multilingual"
]

# Comprehensive wordlist (all combined)
COMPREHENSIVE_WORDLIST = list(set(SECURITY_WORDLIST))

def get_wordlist(wordlist_type: str, custom_wordlist: list = None) -> list:
    """Get wordlist based on type"""
    
    if wordlist_type == "basic":
        return BASIC_WORDLIST
    elif wordlist_type == "common":
        return COMMON_WORDLIST
    elif wordlist_type == "security_focused":
        return SECURITY_WORDLIST
    elif wordlist_type == "comprehensive":
        return COMPREHENSIVE_WORDLIST
    elif wordlist_type == "custom" and custom_wordlist:
        return custom_wordlist
    else:
        # Default to security focused
        return SECURITY_WORDLIST