/**
 * # Terraform Wazuh Kubernetes module
 * ~~~
 * This is experimental module and still in progress
 * ~~~
 * Simple terraform module for deployment [Wazuh](https://wazuh.com/) on Kubernetes
 * Usage:
 *
 * ```hcl
 *  module "wazuh" {
 *      source                            = "../../"
 *      storage_class_create              = false
 *      wazuh_storage_class_name          = "hostpath"
 *      wazuh_manager_storage_size        = "2Gi"
 *      es_datanode_storage_size          = "2Gi"
 *      wazuh_worker_storage_size         = "2Gi"
 *      wazuh_es_memory_limit             = "2Gi"
 *      wazuh_es_memory_request           = "1Gi"
 *      wazuh_es_cpu_request              = "500m"
 *      wazuh_es_cpu_limit                = "1"
 *      wazuh_es_repications              = "1"
 *      wazuh_manager_worker_replications = "1"
 * }
 * ```
 *
 * The example above working fine for dev deployment to Minikube.
 *
 * For production deployment please take a look input parameters.
 * ## Examples
 * You can find simple example in folder `examples/basic`
 * Deploy simple example
 * ```shell
 * cd examples/basic
 * terraform init
 * terraform plan
 * terraform apply
 * ```
 *
 * Destroy
 *
 * ```shell
 * cd examples/basic
 * terraform destroy
 * ```
 *
 */
resource "null_resource" "generate_ssl" {
  triggers = {
    dir_sha1 = sha1(join("", [for f in fileset("files", "*") : filesha1(f)]))
  }
  provisioner "local-exec" {
    working_dir = "${path.module}/files"
    command     = <<-EOF
      openssl genrsa -out root-ca-key.pem 2048
      openssl req -days 3650 -new -x509 -sha256 -key root-ca-key.pem -out root-ca.pem -subj "/C=US/L=California/O=Company/CN=root-ca"
      openssl genrsa -out admin-key-temp.pem 2048
      openssl pkcs8 -inform PEM -outform PEM -in admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out admin-key.pem
      openssl req -days 3650 -new -key admin-key.pem -out admin.csr -subj "/C=US/L=California/O=CompanyUS/CN=admin"
      openssl x509 -req -days 3650 -in admin.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out admin.pem
      openssl genrsa -out node-key-temp.pem 2048
      openssl pkcs8 -inform PEM -outform PEM -in node-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node-key.pem
      openssl req -days 3650 -new -key node-key.pem -out node.csr -subj "/C=US/L=California/O=Company/CN=*.elasticsearch"
      openssl x509 -req -days 3650 -in node.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out node.pem
      openssl genrsa -out kibana-key-temp.pem 2048
      openssl pkcs8 -inform PEM -outform PEM -in kibana-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out kibana-key.pem
      openssl req -days 3650 -new -key kibana-key.pem -out kibana.csr -subj "/C=US/L=California/O=Company/CN=kibana"
      openssl x509 -req -days 3650 -in kibana.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out kibana.pem
      openssl genrsa -out filebeat-key-temp.pem 2048
      openssl pkcs8 -inform PEM -outform PEM -in filebeat-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out filebeat-key.pem
      openssl req -days 3650 -new -key filebeat-key.pem -out filebeat.csr -subj "/C=US/L=California/O=Company/CN=filebeat"
      openssl x509 -req -days 3650 -in filebeat.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out filebeat.pem
EOF
  }
}
resource "null_resource" "clean_certs" {
  provisioner "local-exec" {
    when    = destroy
    command = "rm -rf ${path.module}/files/*"
  }
}
data "local_file" "root_key" {
  depends_on = [null_resource.generate_ssl]
  filename   = "${path.module}/files/root-ca-key.pem"
}
data "local_file" "root_pem" {
  depends_on = [null_resource.generate_ssl]
  filename   = "${path.module}/files/root-ca.pem"
}
data "local_file" "admin_key" {
  depends_on = [null_resource.generate_ssl]
  filename   = "${path.module}/files/admin-key.pem"
}
data "local_file" "admin_pem" {
  depends_on = [null_resource.generate_ssl]
  filename   = "${path.module}/files/admin.pem"
}
data "local_file" "filebeat_key" {
  depends_on = [null_resource.generate_ssl]
  filename   = "${path.module}/files/filebeat-key.pem"
}
data "local_file" "filebeat_pem" {
  depends_on = [null_resource.generate_ssl]
  filename   = "${path.module}/files/filebeat.pem"
}
data "local_file" "kibana_key" {
  depends_on = [null_resource.generate_ssl]
  filename   = "${path.module}/files/kibana-key.pem"
}
data "local_file" "kibana_pem" {
  depends_on = [null_resource.generate_ssl]
  filename   = "${path.module}/files/kibana.pem"
}
data "local_file" "node_key" {
  depends_on = [null_resource.generate_ssl]
  filename   = "${path.module}/files/node-key.pem"
}
data "local_file" "node_pem" {
  depends_on = [null_resource.generate_ssl]
  filename   = "${path.module}/files/node.pem"
}
locals {
  admin_hash = bcrypt(random_password.this.result)
}
resource "kubernetes_namespace" "this" {
  metadata {
    name = var.wazuh_namespace
  }
}
resource "random_password" "this" {
  length  = 16
  special = false
}
resource "random_password" "wazuh_wui" {
  length      = 16
  special     = true
  number      = true
  lower       = true
  upper       = true
  min_numeric = 2
}
resource "random_password" "wazuh_authd_pass" {
  length  = 16
  special = true
  number  = true
  lower   = true
  upper   = true
}
resource "random_password" "wazuh_cluster_key" {
  length  = 32
  special = false
}
resource "kubernetes_storage_class" "this" {
  count               = var.storage_class_create ? 1 : 0
  storage_provisioner = var.storage_provisioner
  metadata {
    name = "${var.prefix}-standard"
  }
  parameters = {
    type = var.storage_provisioner_type
  }
  reclaim_policy = "Retain"
}
data "template_file" "es_template" {
  template = file("${path.module}/templates/elasticsearch.tpl")
  vars = {
    namespace = "${var.prefix}-elasticsearch"
    pod_name  = "${var.prefix}-elasticsearch-0"
  }
}
data "template_file" "es_internal_users" {
  template = file("${path.module}/templates/internal_users.tpl")
  vars = {
    admin_hash = local.admin_hash
  }
}
resource "kubernetes_config_map" "es_config_map" {
  metadata {
    name      = "${var.prefix}-es-config-map"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  data = {
    "elasticsearch.yml"  = data.template_file.es_template.rendered
    "internal_users.yml" = data.template_file.es_internal_users.rendered
  }
  lifecycle { ignore_changes = [data] }
}
data "template_file" "wazuh_master_conf" {
  template = templatefile("${path.module}/templates/master.tpl", {
    email_notification             = var.email_notification
    smtp_server                    = var.smtp_server
    email_from                     = var.email_from
    email_to                       = var.email_to
    queue_size                     = var.queue_size
    log_format                     = var.log_format
    rootcheck_disabled             = var.rootcheck_disabled
    openscap_disabled              = var.openscap_disabled
    ciscat_disabled                = var.ciscat_disabled
    osquery_disabled               = var.osquery_disabled
    syscollector_disabled          = var.syscollector_disabled
    vulnerability_detector_enabled = var.vulnerability_detector_enabled
    syscheck_disabled              = var.syscheck_disabled
    white_lists                    = var.white_lists
  })
}
data "template_file" "wazuh_worker_conf" {
  template = templatefile("${path.module}/templates/worker.tpl", {
    email_notification             = var.email_notification
    smtp_server                    = var.smtp_server
    email_from                     = var.email_from
    email_to                       = var.email_to
    queue_size                     = var.worker_queue_size
    log_format                     = var.worker_log_format
    rootcheck_disabled             = var.worker_rootcheck_disabled
    openscap_disabled              = var.worker_openscap_disabled
    ciscat_disabled                = var.worker_ciscat_disabled
    osquery_disabled               = var.worker_osquery_disabled
    syscollector_disabled          = var.worker_syscollector_disabled
    vulnerability_detector_enabled = var.worker_vulnerability_detector_enabled
    syscheck_disabled              = var.worker_syscheck_disabled
    white_lists                    = var.worker_white_lists
  })
}
resource "kubernetes_config_map" "wazuh_configs" {
  metadata {
    name      = "${var.prefix}-conf"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  data = {
    "master.conf" = data.template_file.wazuh_master_conf.rendered
    "worker.conf" = data.template_file.wazuh_worker_conf.rendered
  }
}
resource "kubernetes_secret" "elastic_cred" {
  metadata {
    name      = "elastic-cred"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  data = {
    password = random_password.this.result
    username = "admin"
  }
}


resource "kubernetes_secret" "kibana_certs" {
  metadata {
    name      = "kibana-certs"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  data = {
    "cert.pem" = data.local_file.kibana_pem.content
    "key.pem"  = data.local_file.kibana_key.content
  }
  type = "Opaque"
}
resource "kubernetes_secret" "wazuh_ssl_certs" {
  depends_on = [null_resource.generate_ssl]
  metadata {
    name      = "${var.prefix}-ssl-certs"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  data = {
    "admin-key.pem"    = data.local_file.admin_key.content
    "admin.pem"        = data.local_file.admin_pem.content
    "filebeat-key.pem" = data.local_file.filebeat_key.content
    "filebeat.pem"     = data.local_file.filebeat_pem.content
    "kibana-key.pem"   = data.local_file.kibana_key.content
    "kibana.pem"       = data.local_file.filebeat_pem.content
    "node-key.pem"     = data.local_file.node_key.content
    "node.pem"         = data.local_file.node_pem.content
    "root-ca.pem"      = data.local_file.root_pem.content
  }
  type = "Opaque"
}
resource "kubernetes_secret" "wazuh_api_cred" {
  metadata {
    name      = "${var.prefix}-api-cred"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  data = {
    password = random_password.wazuh_wui.result

    username = "wazuh-wui"
  }
}
resource "kubernetes_secret" "wazuh_authd_pass" {
  metadata {
    name      = "${var.prefix}-authd-pass"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  data = {
    "authd.pass" = random_password.wazuh_authd_pass.result
  }
}

resource "kubernetes_secret" "wazuh_cluster_key" {
  metadata {
    name      = "${var.prefix}-cluster-key"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  data = {
    key = random_password.wazuh_cluster_key.result
  }
}
resource "kubernetes_service" "elasticsearch" {
  metadata {
    name      = "elasticsearch"
    namespace = kubernetes_namespace.this.metadata[0].name

    labels = {
      app = "${var.prefix}-elasticsearch"
    }
  }

  spec {
    port {
      name        = "es-rest"
      port        = 9200
      target_port = "9200"
    }

    selector = {
      app = "${var.prefix}-elasticsearch"
    }

    type = "LoadBalancer"
  }
}

resource "kubernetes_service" "kibana" {
  metadata {
    name      = "kibana"
    namespace = kubernetes_namespace.this.metadata[0].name

    labels = {
      app = "${var.prefix}-kibana"
    }

  }

  spec {
    port {
      name        = "kibana"
      port        = 443
      target_port = "5601"
    }

    selector = {
      app = "${var.prefix}-kibana"
    }

    type = "LoadBalancer"
  }
}

resource "kubernetes_service" "wazuh_cluster" {
  metadata {
    name      = "${var.prefix}-cluster"
    namespace = kubernetes_namespace.this.metadata[0].name

    labels = {
      app = "${var.prefix}-manager"
    }
  }

  spec {
    port {
      name        = "cluster"
      port        = 1516
      target_port = "1516"
    }

    selector = {
      app = "${var.prefix}-manager"
    }

    cluster_ip = "None"
  }
}

resource "kubernetes_service" "wazuh_elasticsearch" {
  metadata {
    name      = "${var.prefix}-elasticsearch"
    namespace = kubernetes_namespace.this.metadata[0].name

    labels = {
      app = "${var.prefix}-elasticsearch"
    }
  }

  spec {
    port {
      name        = "es-nodes"
      port        = 9300
      target_port = "9300"
    }

    selector = {
      app = "${var.prefix}-elasticsearch"
    }

    cluster_ip = "None"
  }
}

resource "kubernetes_service" "wazuh_workers" {
  metadata {
    name      = "${var.prefix}-workers"
    namespace = kubernetes_namespace.this.metadata[0].name

    labels = {
      app = "${var.prefix}-manager"
    }

  }

  spec {
    port {
      name        = "agents-events"
      port        = 1514
      target_port = "1514"
    }

    selector = {
      app = "${var.prefix}-manager"

      node-type = "worker"
    }

    type = "LoadBalancer"
  }
}

resource "kubernetes_service" "wazuh" {
  metadata {
    name      = "wazuh"
    namespace = kubernetes_namespace.this.metadata[0].name

    labels = {
      app = "${var.prefix}-manager"
    }

  }

  spec {
    port {
      name        = "registration"
      port        = 1515
      target_port = "1515"
    }

    port {
      name        = "api"
      port        = 55000
      target_port = "55000"
    }

    selector = {
      app = "${var.prefix}-manager"

      node-type = "master"
    }

    type = "LoadBalancer"
  }
}
resource "kubernetes_deployment" "wazuh_kibana" {
  depends_on = [kubernetes_stateful_set.wazuh_elasticsearch]
  metadata {
    name      = "${var.prefix}-kibana"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "${var.prefix}-kibana"
      }
    }

    template {
      metadata {
        name = "${var.prefix}-kibana"

        labels = {
          app = "${var.prefix}-kibana"
        }
      }

      spec {
        volume {
          name = "kibana-certs"

          secret {
            secret_name = kubernetes_secret.kibana_certs.metadata[0].name
          }
        }

        container {
          name  = "${var.prefix}-kibana"
          image = var.kibana_default_image

          port {
            name           = "kibana"
            container_port = 5601
          }

          env {
            name  = "ELASTICSEARCH_URL"
            value = "https://${var.prefix}-elasticsearch-0.${var.prefix}-elasticsearch:9200"
          }

          env {
            name = "ELASTICSEARCH_USERNAME"

            value_from {
              secret_key_ref {
                name = kubernetes_secret.elastic_cred.metadata[0].name
                key  = "username"
              }
            }
          }

          env {
            name = "ELASTICSEARCH_PASSWORD"

            value_from {
              secret_key_ref {
                name = kubernetes_secret.elastic_cred.metadata[0].name
                key  = "password"
              }
            }
          }

          env {
            name  = "SERVER_SSL_ENABLED"
            value = "true"
          }

          env {
            name  = "SERVER_SSL_CERTIFICATE"
            value = "/usr/share/kibana/config/cert.pem"
          }

          env {
            name  = "SERVER_SSL_KEY"
            value = "/usr/share/kibana/config/key.pem"
          }

          env {
            name  = "WAZUH_API_URL"
            value = "https://${var.prefix}-manager-master-0.wazuh-cluster"
          }

          env {
            name = "API_USERNAME"

            value_from {
              secret_key_ref {
                name = kubernetes_secret.wazuh_api_cred.metadata[0].name
                key  = "username"
              }
            }
          }

          env {
            name = "API_PASSWORD"

            value_from {
              secret_key_ref {
                name = kubernetes_secret.wazuh_api_cred.metadata[0].name
                key  = "password"
              }
            }
          }
          resources {
            limits = {
              cpu    = "400m"
              memory = "2Gi"
            }

            requests = {
              cpu    = "200m"
              memory = "512Mi"
            }
          }

          volume_mount {
            name       = kubernetes_secret.kibana_certs.metadata[0].name
            read_only  = true
            mount_path = "/usr/share/kibana/config/cert.pem"
            sub_path   = "cert.pem"
          }

          volume_mount {
            name       = kubernetes_secret.kibana_certs.metadata[0].name
            read_only  = true
            mount_path = "/usr/share/kibana/config/key.pem"
            sub_path   = "key.pem"
          }
        }
      }
    }
  }
}
resource "kubernetes_stateful_set" "wazuh_elasticsearch" {
  metadata {
    name      = "${var.prefix}-elasticsearch"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  spec {
    replicas = var.wazuh_es_repications

    selector {
      match_labels = {
        app = "${var.prefix}-elasticsearch"
      }
    }

    template {
      metadata {
        name = "${var.prefix}-elasticsearch"

        labels = {
          app = "${var.prefix}-elasticsearch"
        }
      }

      spec {
        volume {
          name = "odfe-ssl-certs"

          secret {
            secret_name = kubernetes_secret.wazuh_ssl_certs.metadata[0].name
          }
        }

        volume {
          name = "elastic-odfe-conf"

          config_map {
            name = kubernetes_config_map.es_config_map.metadata[0].name
          }
        }

        init_container {
          name    = "volume-mount-hack"
          image   = var.init_container_image
          command = ["sh", "-c", "chown -R 1000:1000 /usr/share/elasticsearch/data"]

          resources {
            limits = {
              cpu    = "100m"
              memory = "256Mi"
            }

            requests = {
              cpu    = "50m"
              memory = "128Mi"
            }
          }

          volume_mount {
            name       = "${var.prefix}-elasticsearch"
            mount_path = "/usr/share/elasticsearch/data"
          }
        }

        init_container {
          name    = "increase-the-vm-max-map-count"
          image   = var.init_container_image
          command = ["sysctl", "-w", "vm.max_map_count=262144"]

          security_context {
            privileged = true
          }
        }

        container {
          name  = "${var.prefix}-elasticsearch"
          image = var.opendistro_default_image

          port {
            name           = "es-rest"
            container_port = 9200
          }

          port {
            name           = "es-nodes"
            container_port = 9300
          }

          env {
            name  = "ES_JAVA_OPTS"
            value = "-Xms1g -Xmx1g"
          }

          env {
            name  = "CLUSTER_NAME"
            value = "wazuh"
          }

          env {
            name  = "NETWORK_HOST"
            value = "0.0.0.0"
          }

          env {
            name = "NODE_NAME"

            value_from {
              field_ref {
                field_path = "metadata.name"
              }
            }
          }

          env {
            name  = "DISCOVERY_SERVICE"
            value = "${var.prefix}-elasticsearch"
          }

          env {
            name = "KUBERNETES_NAMESPACE"

            value_from {
              field_ref {
                field_path = "metadata.namespace"
              }
            }
          }

          env {
            name  = "DISABLE_INSTALL_DEMO_CONFIG"
            value = "true"
          }

          resources {
            limits = {
              memory = var.wazuh_es_memory_limit
              cpu    = var.wazuh_es_cpu_limit
            }

            requests = {
              cpu    = var.wazuh_es_cpu_request
              memory = var.wazuh_es_memory_request
            }
          }

          volume_mount {
            name       = "${var.prefix}-elasticsearch"
            mount_path = "/usr/share/elasticsearch/data"
          }

          volume_mount {
            name       = "odfe-ssl-certs"
            read_only  = true
            mount_path = "/usr/share/elasticsearch/config/node-key.pem"
            sub_path   = "node-key.pem"
          }

          volume_mount {
            name       = "odfe-ssl-certs"
            read_only  = true
            mount_path = "/usr/share/elasticsearch/config/node.pem"
            sub_path   = "node.pem"
          }

          volume_mount {
            name       = "odfe-ssl-certs"
            read_only  = true
            mount_path = "/usr/share/elasticsearch/config/root-ca.pem"
            sub_path   = "root-ca.pem"
          }

          volume_mount {
            name       = "odfe-ssl-certs"
            read_only  = true
            mount_path = "/usr/share/elasticsearch/config/admin.pem"
            sub_path   = "admin.pem"
          }

          volume_mount {
            name       = "odfe-ssl-certs"
            read_only  = true
            mount_path = "/usr/share/elasticsearch/config/admin-key.pem"
            sub_path   = "admin-key.pem"
          }

          volume_mount {
            name       = "elastic-odfe-conf"
            read_only  = true
            mount_path = "/usr/share/elasticsearch/config/elasticsearch.yml"
            sub_path   = "elasticsearch.yml"
          }

          volume_mount {
            name       = "elastic-odfe-conf"
            read_only  = true
            mount_path = "/usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml"
            sub_path   = "internal_users.yml"
          }

          security_context {
            capabilities {
              add = ["SYS_CHROOT"]
            }
          }
        }
      }
    }

    volume_claim_template {
      metadata {
        name      = "${var.prefix}-elasticsearch"
        namespace = kubernetes_namespace.this.metadata[0].name
      }

      spec {
        access_modes = ["ReadWriteOnce"]

        resources {
          requests = {
            storage = var.es_datanode_storage_size
          }
        }

        storage_class_name = var.wazuh_storage_class_name != "" ? var.wazuh_storage_class_name : "${var.prefix}-standard"
      }
    }

    service_name = "${var.prefix}-elasticsearch"
  }
}

resource "kubernetes_stateful_set" "wazuh_manager_master" {
  metadata {
    name      = "${var.prefix}-manager-master"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "${var.prefix}-manager"

        node-type = "master"
      }
    }

    template {
      metadata {
        name = "${var.prefix}-manager-master"

        labels = {
          app = "${var.prefix}-manager"

          node-type = "master"
        }
      }

      spec {
        volume {
          name = "config"

          config_map {
            name = kubernetes_config_map.wazuh_configs.metadata[0].name
          }
        }

        volume {
          name = "filebeat-certs"

          secret {
            secret_name = kubernetes_secret.wazuh_ssl_certs.metadata[0].name
          }
        }

        volume {
          name = "wazuh-authd-pass"

          secret {
            secret_name = kubernetes_secret.wazuh_authd_pass.metadata[0].name
          }
        }

        container {
          name  = "wazuh-manager"
          image = var.wazuh_default_image

          port {
            name           = "registration"
            container_port = 1515
          }

          port {
            name           = "cluster"
            container_port = 1516
          }

          port {
            name           = "api"
            container_port = 55000
          }

          env {
            name  = "ELASTICSEARCH_URL"
            value = "https://${var.prefix}-elasticsearch-0.${var.prefix}-elasticsearch:9200"
          }

          env {
            name = "ELASTIC_USERNAME"

            value_from {
              secret_key_ref {
                name = "elastic-cred"
                key  = "username"
              }
            }
          }

          env {
            name = "ELASTIC_PASSWORD"

            value_from {
              secret_key_ref {
                name = "elastic-cred"
                key  = "password"
              }
            }
          }

          env {
            name  = "FILEBEAT_SSL_VERIFICATION_MODE"
            value = "none"
          }

          env {
            name  = "SSL_CERTIFICATE_AUTHORITIES"
            value = "/etc/ssl/root-ca.pem"
          }

          env {
            name  = "SSL_CERTIFICATE"
            value = "/etc/ssl/filebeat.pem"
          }

          env {
            name  = "SSL_KEY"
            value = "/etc/ssl/filebeat.key"
          }

          env {
            name = "API_USERNAME"

            value_from {
              secret_key_ref {
                name = "wazuh-api-cred"
                key  = "username"
              }
            }
          }

          env {
            name = "API_PASSWORD"

            value_from {
              secret_key_ref {
                name = "wazuh-api-cred"
                key  = "password"
              }
            }
          }

          env {
            name = "WAZUH_CLUSTER_KEY"

            value_from {
              secret_key_ref {
                name = "wazuh-cluster-key"
                key  = "key"
              }
            }
          }

          resources {
            limits = {
              cpu    = var.wazuh_manager_cpu_limit
              memory = var.wazuh_manager_memory_limit
            }

            requests = {
              cpu    = var.wazuh_manager_cpu_request
              memory = var.wazuh_manager_memory_request
            }
          }

          volume_mount {
            name       = "config"
            read_only  = true
            mount_path = "/wazuh-config-mount/etc/ossec.conf"
            sub_path   = "master.conf"
          }

          volume_mount {
            name       = "filebeat-certs"
            read_only  = true
            mount_path = "/etc/ssl/root-ca.pem"
            sub_path   = "root-ca.pem"
          }

          volume_mount {
            name       = "filebeat-certs"
            read_only  = true
            mount_path = "/etc/ssl/filebeat.pem"
            sub_path   = "filebeat.pem"
          }

          volume_mount {
            name       = "filebeat-certs"
            read_only  = true
            mount_path = "/etc/ssl/filebeat.key"
            sub_path   = "filebeat-key.pem"
          }

          volume_mount {
            name       = "wazuh-authd-pass"
            read_only  = true
            mount_path = "/wazuh-config-mount/etc/authd.pass"
            sub_path   = "authd.pass"
          }

          volume_mount {
            name       = "wazuh-manager-master"
            mount_path = "/var/ossec/api/configuration"
            sub_path   = "wazuh/var/ossec/api/configuration"
          }

          volume_mount {
            name       = "wazuh-manager-master"
            mount_path = "/var/ossec/etc"
            sub_path   = "wazuh/var/ossec/etc"
          }

          volume_mount {
            name       = "wazuh-manager-master"
            mount_path = "/var/ossec/logs"
            sub_path   = "wazuh/var/ossec/logs"
          }

          volume_mount {
            name       = "wazuh-manager-master"
            mount_path = "/var/ossec/queue"
            sub_path   = "wazuh/var/ossec/queue"
          }

          volume_mount {
            name       = "wazuh-manager-master"
            mount_path = "/var/ossec/var/multigroups"
            sub_path   = "wazuh/var/ossec/var/multigroups"
          }

          volume_mount {
            name       = "wazuh-manager-master"
            mount_path = "/var/ossec/integrations"
            sub_path   = "wazuh/var/ossec/integrations"
          }

          volume_mount {
            name       = "wazuh-manager-master"
            mount_path = "/var/ossec/active-response/bin"
            sub_path   = "wazuh/var/ossec/active-response/bin"
          }

          volume_mount {
            name       = "wazuh-manager-master"
            mount_path = "/var/ossec/agentless"
            sub_path   = "wazuh/var/ossec/agentless"
          }

          volume_mount {
            name       = "wazuh-manager-master"
            mount_path = "/var/ossec/wodles"
            sub_path   = "wazuh/var/ossec/wodles"
          }

          volume_mount {
            name       = "wazuh-manager-master"
            mount_path = "/etc/filebeat"
            sub_path   = "filebeat/etc/filebeat"
          }

          volume_mount {
            name       = "wazuh-manager-master"
            mount_path = "/var/lib/filebeat"
            sub_path   = "filebeat/var/lib/filebeat"
          }

          security_context {
            capabilities {
              add = ["SYS_CHROOT"]
            }
          }
        }
      }
    }

    volume_claim_template {
      metadata {
        name      = "${var.prefix}-manager-master"
        namespace = kubernetes_namespace.this.metadata[0].name
      }

      spec {
        access_modes = ["ReadWriteOnce"]

        resources {
          requests = {
            storage = var.wazuh_manager_storage_size
          }
        }

        storage_class_name = var.wazuh_storage_class_name != "" ? var.wazuh_storage_class_name : "${var.prefix}-standard"
      }
    }

    service_name          = "${var.prefix}-cluster"
    pod_management_policy = "Parallel"
  }
}

resource "kubernetes_stateful_set" "wazuh_manager_worker" {
  metadata {
    name      = "${var.prefix}-manager-worker"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  spec {
    replicas = var.wazuh_manager_worker_replications

    selector {
      match_labels = {
        app       = "${var.prefix}-manager"
        node-type = "worker"
      }
    }

    template {
      metadata {
        name = "${var.prefix}-manager-worker"

        labels = {
          app       = "${var.prefix}-manager"
          node-type = "worker"
        }
      }

      spec {
        volume {
          name = "config"

          config_map {
            name = kubernetes_config_map.wazuh_configs.metadata[0].name
          }
        }

        volume {
          name = "filebeat-certs"

          secret {
            secret_name = kubernetes_secret.wazuh_ssl_certs.metadata[0].name
          }
        }

        container {
          name  = "wazuh-manager"
          image = var.wazuh_default_image

          port {
            name           = "agents-events"
            container_port = 1514
          }

          port {
            name           = "cluster"
            container_port = 1516
          }

          env {
            name  = "ELASTICSEARCH_URL"
            value = "https://${var.prefix}-elasticsearch-0.${var.prefix}-elasticsearch:9200"
          }

          env {
            name = "ELASTIC_USERNAME"

            value_from {
              secret_key_ref {
                name = "elastic-cred"
                key  = "username"
              }
            }
          }

          env {
            name = "ELASTIC_PASSWORD"

            value_from {
              secret_key_ref {
                name = "elastic-cred"
                key  = "password"
              }
            }
          }

          env {
            name  = "FILEBEAT_SSL_VERIFICATION_MODE"
            value = "none"
          }

          env {
            name  = "SSL_CERTIFICATE_AUTHORITIES"
            value = "/etc/ssl/root-ca.pem"
          }

          env {
            name  = "SSL_CERTIFICATE"
            value = "/etc/ssl/filebeat.pem"
          }

          env {
            name  = "SSL_KEY"
            value = "/etc/ssl/filebeat.key"
          }

          env {
            name = "WAZUH_CLUSTER_KEY"

            value_from {
              secret_key_ref {
                name = "wazuh-cluster-key"
                key  = "key"
              }
            }
          }

          resources {
            limits = {
              cpu    = var.wazuh_worker_cpu_limit
              memory = var.wazuh_worker_memory_limit
            }

            requests = {
              cpu    = var.wazuh_worker_cpu_request
              memory = var.wazuh_worker_memory_request
            }
          }

          volume_mount {
            name       = "config"
            read_only  = true
            mount_path = "/wazuh-config-mount/etc/ossec.conf"
            sub_path   = "worker.conf"
          }

          volume_mount {
            name       = "filebeat-certs"
            read_only  = true
            mount_path = "/etc/ssl/root-ca.pem"
            sub_path   = "root-ca.pem"
          }

          volume_mount {
            name       = "filebeat-certs"
            read_only  = true
            mount_path = "/etc/ssl/filebeat.pem"
            sub_path   = "filebeat.pem"
          }

          volume_mount {
            name       = "filebeat-certs"
            read_only  = true
            mount_path = "/etc/ssl/filebeat.key"
            sub_path   = "filebeat-key.pem"
          }

          volume_mount {
            name       = "wazuh-manager-worker"
            mount_path = "/var/ossec/api/configuration"
            sub_path   = "wazuh/var/ossec/api/configuration"
          }

          volume_mount {
            name       = "wazuh-manager-worker"
            mount_path = "/var/ossec/etc"
            sub_path   = "wazuh/var/ossec/etc"
          }

          volume_mount {
            name       = "wazuh-manager-worker"
            mount_path = "/var/ossec/logs"
            sub_path   = "wazuh/var/ossec/logs"
          }

          volume_mount {
            name       = "wazuh-manager-worker"
            mount_path = "/var/ossec/queue"
            sub_path   = "wazuh/var/ossec/queue"
          }

          volume_mount {
            name       = "wazuh-manager-worker"
            mount_path = "/var/ossec/var/multigroups"
            sub_path   = "wazuh/var/ossec/var/multigroups"
          }

          volume_mount {
            name       = "wazuh-manager-worker"
            mount_path = "/var/ossec/integrations"
            sub_path   = "wazuh/var/ossec/integrations"
          }

          volume_mount {
            name       = "wazuh-manager-worker"
            mount_path = "/var/ossec/active-response/bin"
            sub_path   = "wazuh/var/ossec/active-response/bin"
          }

          volume_mount {
            name       = "wazuh-manager-worker"
            mount_path = "/var/ossec/agentless"
            sub_path   = "wazuh/var/ossec/agentless"
          }

          volume_mount {
            name       = "wazuh-manager-worker"
            mount_path = "/var/ossec/wodles"
            sub_path   = "wazuh/var/ossec/wodles"
          }

          volume_mount {
            name       = "wazuh-manager-worker"
            mount_path = "/etc/filebeat"
            sub_path   = "filebeat/etc/filebeat"
          }

          volume_mount {
            name       = "wazuh-manager-worker"
            mount_path = "/var/lib/filebeat"
            sub_path   = "filebeat/var/lib/filebeat"
          }

          security_context {
            capabilities {
              add = ["SYS_CHROOT"]
            }
          }
        }

        affinity {
          pod_anti_affinity {
            preferred_during_scheduling_ignored_during_execution {
              weight = 100

              pod_affinity_term {
                topology_key = "kubernetes.io/hostname"
              }
            }
          }
        }
      }
    }

    volume_claim_template {
      metadata {
        name      = "${var.prefix}-manager-worker"
        namespace = kubernetes_namespace.this.metadata[0].name
      }

      spec {
        access_modes = ["ReadWriteOnce"]

        resources {
          requests = {
            storage = var.wazuh_worker_storage_size
          }
        }

        storage_class_name = var.wazuh_storage_class_name != "" ? var.wazuh_storage_class_name : "${var.prefix}-standard"
      }
    }

    service_name          = "${var.prefix}-cluster"
    pod_management_policy = "Parallel"
  }
}

resource "kubernetes_daemonset" "wazuh_agent" {
  depends_on = [
    kubernetes_stateful_set.wazuh_elasticsearch,
    kubernetes_stateful_set.wazuh_manager_master,
    kubernetes_stateful_set.wazuh_manager_worker
  ]

  count = var.wazuh_agent_enabled ? 1 : 0
  metadata {
    name      = "${var.prefix}-agent"
    namespace = kubernetes_namespace.this.metadata[0].name
  }

  spec {
    selector {
      match_labels = {
        app = "${var.prefix}-agent"
      }
    }

    template {
      metadata {
        name = "${var.prefix}-agent"

        labels = {
          app = "${var.prefix}-agent"
        }
      }

      spec {
        volume {
          name = "docker-socket-mount"

          host_path {
            path = "/var/run/docker.sock"
          }
        }

        volume {
          name = "var-run"

          host_path {
            path = "/var/run"
          }
        }

        volume {
          name = "dev"

          host_path {
            path = "/dev"
          }
        }

        volume {
          name = "sys"

          host_path {
            path = "/sys"
          }
        }

        volume {
          name = "proc"

          host_path {
            path = "/proc"
          }
        }

        volume {
          name = "etc"

          host_path {
            path = "/etc"
          }
        }

        volume {
          name = "boot"

          host_path {
            path = "/boot"
          }
        }

        volume {
          name = "usr"

          host_path {
            path = "/usr"
          }
        }

        volume {
          name = "modules"

          host_path {
            path = "/lib/modules"
          }
        }

        volume {
          name = "log"

          host_path {
            path = "/var/logs"
          }
        }

        container {
          name  = "${var.prefix}-agent"
          image = var.wazuh_agent_default_image

          port {
            name           = "agent-http"
            container_port = 5000
            protocol       = "TCP"
          }

          env {
            name  = "JOIN_MANAGER"
            value = "${var.prefix}.${var.wazuh_namespace}.svc.cluster.local"
          }

          env {
            name  = "JOIN_MANAGER_MASTER_HOST"
            value = "${var.prefix}.${var.wazuh_namespace}.svc.cluster.local"
          }

          env {
            name  = "JOIN_MANAGER_WORKER_HOST"
            value = "${var.prefix}-workers.${var.wazuh_namespace}.svc.cluster.local"
          }

          env {
            name  = "JOIN_MANAGER_PROTOCOL"
            value = "https"
          }

          env {
            name = "NODE_NAME"

            value_from {
              field_ref {
                field_path = "spec.nodeName"
              }
            }
          }

          env {
            name  = "WAZUH_GROUPS"
            value = "default"
          }

          env {
            name  = "JOIN_PASSWORD"
            value = "password"
          }

          env {
            name = "JOIN_MANAGER_USER"

            value_from {
              secret_key_ref {
                name = "wazuh-api-cred"
                key  = "username"
              }
            }
          }

          env {
            name = "JOIN_MANAGER_PASSWORD"

            value_from {
              secret_key_ref {
                name = "wazuh-api-cred"
                key  = "password"
              }
            }
          }

          env {
            name  = "JOIN_MANAGER_API_PORT"
            value = "55000"
          }

          env {
            name  = "JOIN_MANAGER_PORT"
            value = "1514"
          }

          env {
            name  = "HEALTH_CHECK_PROCESSES"
            value = "ossec-execd,ossec-syscheckd,ossec-logcollector,wazuh-modulesd,ossec-authd"
          }

          resources {
            limits = {
              memory = "512Mi"
            }
          }

          volume_mount {
            name       = "var-run"
            mount_path = "/var/run"
          }

          volume_mount {
            name       = "dev"
            mount_path = "/host/dev"
          }

          volume_mount {
            name       = "sys"
            read_only  = true
            mount_path = "/host/sys"
          }

          volume_mount {
            name       = "proc"
            read_only  = true
            mount_path = "/host/proc"
          }

          volume_mount {
            name       = "etc"
            read_only  = true
            mount_path = "/host/etc"
          }

          volume_mount {
            name       = "docker-socket-mount"
            mount_path = "/var/run/docker.sock"
          }

          volume_mount {
            name       = "docker-socket-mount"
            mount_path = "/host/var/run/docker.sock"
          }

          volume_mount {
            name       = "boot"
            read_only  = true
            mount_path = "/host/boot"
          }

          volume_mount {
            name       = "usr"
            read_only  = true
            mount_path = "/host/usr"
          }

          volume_mount {
            name       = "modules"
            read_only  = true
            mount_path = "/host/lib/modules"
          }

          volume_mount {
            name       = "log"
            read_only  = true
            mount_path = "/host/var/log"
          }

          liveness_probe {
            http_get {
              path = "/healz"
              port = "5000"
            }

            initial_delay_seconds = 20
            timeout_seconds       = 10
            period_seconds        = 10
            failure_threshold     = 3
          }

          image_pull_policy = "Always"

          security_context {
            privileged = true
          }
        }

        host_pid = true
        host_ipc = true
      }
    }
  }
}
