module "wazuh" {
  source                            = "../../"
  storage_class_create              = false
  wazuh_storage_class_name          = "hostpath"
  wazuh_manager_storage_size        = "2Gi"
  es_datanode_storage_size          = "2Gi"
  wazuh_worker_storage_size         = "2Gi"
  wazuh_es_memory_limit             = "2Gi"
  wazuh_es_memory_request           = "1Gi"
  wazuh_es_cpu_request              = "500m"
  wazuh_es_cpu_limit                = "1"
  wazuh_es_repications              = "1"
  wazuh_manager_worker_replications = "1"
}
output "admin_password" {
  value = module.wazuh.admin_password
}
