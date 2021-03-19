variable "wazuh_namespace" {
  default     = "wazuh"
  description = "Wazuh Kubernetes namespace"
  type        = string
}
variable "storage_class_create" {
  description = "Create or Not Kubernetes storage class"
  type        = bool
}
variable "storage_provisioner" {
  default     = ""
  description = "Kubernetes storage class for Wazuh for example kubernetes.io/gce-pd"
  type        = string
}
variable "storage_provisioner_type" {
  default     = ""
  description = "Kubernetes Storage type. Need to setup only if storage_class_create is true"
}
variable "wazuh_storage_class_name" {
  description = "Kubernetes storage class name"
  type        = string
}
variable "prefix" {
  default     = "wazuh"
  description = "Wazuh naming convention"
  type        = string
}
variable "init_container_image" {
  default     = "busybox"
  description = "Default image for init container"
  type        = string
}
variable "email_notification" {
  default     = "no"
  description = "This toggles the use of email alerting"
  type        = string
}
variable "smtp_server" {
  default     = "smtp.example.wazuh.com"
  description = "This option defines what SMTP server to use to deliver alerts."
  type        = string
}
variable "email_from" {
  default     = "ossecm@example.wazuh.com"
  description = "This specifies the source address contained in the email alerts."
  type        = string
}
variable "email_to" {
  default     = "ecipient@example.wazuh.com"
  description = "This specifies the reply-to address contained in the email alerts."
  type        = string
}
variable "queue_size" {
  default     = "131072"
  description = "This sets the size of the message input buffer in Analysisd (number of events)."
  type        = string
}
variable "log_format" {
  default     = "plain"
  description = " Choose between \"plain\", \"json\", or \"plain,json\" for the format of internal logs"
  type        = string
}
variable "rootcheck_disabled" {
  default     = "no"
  description = "Disables the execution of rootcheck"
  type        = string
}
variable "openscap_disabled" {
  default     = "yes"
  description = "Configuration options of the OpenSCAP wodle"
  type        = string
}
variable "ciscat_disabled" {
  default     = "yes"
  description = "Configuration options of the CIS-CAT wodle."
  type        = string
}
variable "osquery_disabled" {
  default     = "yes"
  description = "Configuration options of the osquery wodle.Osquery is not installed by default. It is an open source software that you have to obtain for using this module."
  type        = string
}
variable "syscollector_disabled" {
  default     = "no"
  description = "Configuration options of the Syscollector wodle for system inventory."
  type        = string
}
variable "vulnerability_detector_enabled" {
  default     = "no"
  description = "This section covers the configuration for the Vulnerability detection module."
  type        = string
}
variable "syscheck_disabled" {
  default     = "no"
  description = "File integrity monitoring"
  type        = string
}
variable "white_lists" {
  default     = []
  description = "This specifies an IP for which Active Responses will not be triggered. Only one IP may be specified for each <while_list> tag, but several IPs may be used by including multiple <white_list> tags."
  type        = list(string)
}
variable "worker_queue_size" {
  default     = "131072"
  description = "This sets the size of the message input buffer in Analysisd (number of events)."
  type        = string
}
variable "worker_log_format" {
  default     = "plain"
  description = " Choose between \"plain\", \"json\", or \"plain,json\" for the format of internal logs"
  type        = string
}
variable "worker_rootcheck_disabled" {
  default     = "no"
  description = "Disables the execution of rootcheck"
  type        = string
}
variable "worker_openscap_disabled" {
  default     = "yes"
  description = "Configuration options of the OpenSCAP wodle"
  type        = string
}
variable "worker_ciscat_disabled" {
  default     = "yes"
  description = "Configuration options of the CIS-CAT wodle."
  type        = string
}
variable "worker_osquery_disabled" {
  default     = "yes"
  description = "Configuration options of the osquery wodle.Osquery is not installed by default. It is an open source software that you have to obtain for using this module."
  type        = string
}
variable "worker_syscollector_disabled" {
  default     = "no"
  description = "Configuration options of the Syscollector wodle for system inventory."
  type        = string
}
variable "worker_vulnerability_detector_enabled" {
  default     = "no"
  description = "This section covers the configuration for the Vulnerability detection module."
  type        = string
}
variable "worker_syscheck_disabled" {
  default     = "no"
  description = "File integrity monitoring"
  type        = string
}
variable "worker_white_lists" {
  default     = []
  description = "This specifies an IP for which Active Responses will not be triggered. Only one IP may be specified for each <while_list> tag, but several IPs may be used by including multiple <white_list> tags."
  type        = list(string)
}

variable "kibana_default_image" {
  default     = "wazuh/wazuh-kibana-odfe:4.1.1"
  description = "Wazuh kibana default image"
  type        = string
}
variable "wazuh_es_repications" {
  default     = 3
  description = "Opendistro stateful set replications set"
  type        = string
}
variable "es_datanode_storage_size" {
  default     = "50Gi"
  description = "Storage size for ES datanodes"
  type        = string
}
variable "wazuh_es_memory_request" {
  default     = "100Mi"
  description = "Opendistro memory request"
  type        = string
}
variable "wazuh_es_memory_limit" {
  default     = "500Mi"
  description = "Opendistro memory limit"
  type        = string
}
variable "wazuh_es_cpu_request" {
  default     = "100m"
  description = "Opendistro cpu request"
  type        = string
}
variable "wazuh_es_cpu_limit" {
  default     = "500m"
  description = "Opendistro cpu limit"
  type        = string
}
variable "opendistro_default_image" {
  default     = "amazon/opendistro-for-elasticsearch:1.12.0"
  description = "Opendistro base image"
  type        = string
}
variable "wazuh_default_image" {
  default     = "wazuh/wazuh-odfe:4.1.1"
  description = "Wazuh manager default image"
  type        = string
}
variable "wazuh_manager_memory_request" {
  default     = "100Mi"
  description = "Wazuh manager memory request"
  type        = string
}
variable "wazuh_manager_memory_limit" {
  default     = "500Mi"
  description = "Wazuh manager memory limit"
  type        = string
}
variable "wazuh_manager_cpu_request" {
  default     = "100m"
  description = "Wazuh manager cpu request"
  type        = string
}
variable "wazuh_manager_cpu_limit" {
  default     = "500m"
  description = "Wazuh manager cpu limit"
  type        = string
}
variable "wazuh_manager_storage_size" {
  default     = "50Gi"
  description = "Storage size of Wazuh manager"
  type        = string
}
variable "wazuh_manager_worker_replications" {
  default     = 2
  description = "Wazuh worker replications count"
  type        = string
}
variable "wazuh_worker_memory_request" {
  default     = "100Mi"
  description = "Wazuh worker memory request"
  type        = string
}
variable "wazuh_worker_memory_limit" {
  default     = "1000Mi"
  description = "Wazuh worker memory limit"
  type        = string
}
variable "wazuh_worker_cpu_request" {
  default     = "100m"
  description = "Wazuh worker cpu request"
  type        = string
}
variable "wazuh_worker_cpu_limit" {
  default     = "1"
  description = "Wazuh worker cpu limit"
  type        = string
}
variable "wazuh_worker_storage_size" {
  default     = "50Gi"
  description = "Storage size of Wazuh worker"
  type        = string
}
variable "wazuh_agent_enabled" {
  default     = false
  description = "Enable or disabled deploy of Wazuh agent DaemonSet"
  type        = bool
}
variable "wazuh_agent_default_image" {
  default     = "kennyopennix/wazuh-agent:latest"
  description = "Wazuh agent image"
  type        = string
}
