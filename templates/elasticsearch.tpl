cluster.name: $${CLUSTER_NAME}
node.name: $${NODE_NAME}
network.host: $${NETWORK_HOST}
discovery.seed_hosts: ${pod_name}.${namespace}
cluster.initial_master_nodes:
  - ${pod_name}

opendistro_security.ssl.transport.enabled: true
opendistro_security.ssl.transport.pemcert_filepath: node.pem
opendistro_security.ssl.transport.pemkey_filepath: node-key.pem
opendistro_security.ssl.transport.pemtrustedcas_filepath: root-ca.pem
opendistro_security.ssl.transport.enforce_hostname_verification: false
opendistro_security.ssl.http.enabled: true
opendistro_security.ssl.http.pemcert_filepath: node.pem
opendistro_security.ssl.http.pemkey_filepath: node-key.pem
opendistro_security.ssl.http.pemtrustedcas_filepath: root-ca.pem
opendistro_security.audit.type: internal_elasticsearch
opendistro_security.audit.config.index: "'security-auditlog-'YYYY.MM"
opendistro_security.allow_default_init_securityindex: true
opendistro_security.allow_unsafe_democertificates: true
opendistro_security.authcz.admin_dn:
  - CN=admin,O=Company,L=California,C=US
opendistro_security.nodes_dn:
  - CN=*.elasticsearch,O=Company,L=California,C=US
opendistro_security.enable_snapshot_restore_privilege: true
opendistro_security.check_snapshot_restore_write_privileges: true
opendistro_security.restapi.roles_enabled: ["all_access", "security_rest_api_access", "service_full_access"]

cluster.routing.allocation.disk.threshold_enabled: false
