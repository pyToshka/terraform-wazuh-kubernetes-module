---
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "${admin_hash}"
  reserved: true
  backend_roles:
  - "admin"
  description: "Demo admin user"

kibanaserver:
  hash: "${admin_hash}"
  reserved: true
  description: "Demo kibanaserver user"

logstash:
  hash: "${admin_hash}"
  reserved: false
  backend_roles:
  - "logstash"
  description: "Demo logstash user"
