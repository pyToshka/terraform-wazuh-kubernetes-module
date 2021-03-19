<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
# Terraform Wazuh Kubernetes module
~~~  
This is experimental module and still in progress
~~~  
Simple terraform module for deployment [Wazuh](https://wazuh.com/) on Kubernetes  
Usage:

```hcl
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
```

The example above working fine for dev deployment to Minikube.

For production deployment please take a look input parameters.
## Examples  
You can find simple example in folder `examples/basic`  
Deploy simple example
```shell
cd examples/basic
terraform init
terraform plan
terraform apply
```

Destroy

```shell
cd examples/basic
terraform destroy
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 0.13 |
| kubernetes | >= 2.0.2 |
| local | >= 2.1.0 |
| null | >= 3.1.0 |
| random | >= 3.1.0 |
| template | >= 2.2.0 |

## Providers

| Name | Version |
|------|---------|
| kubernetes | >= 2.0.2 |
| local | >= 2.1.0 |
| null | >= 3.1.0 |
| random | >= 3.1.0 |
| template | >= 2.2.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| ciscat\_disabled | Configuration options of the CIS-CAT wodle. | `string` | `"yes"` | no |
| email\_from | This specifies the source address contained in the email alerts. | `string` | `"ossecm@example.wazuh.com"` | no |
| email\_notification | This toggles the use of email alerting | `string` | `"no"` | no |
| email\_to | This specifies the reply-to address contained in the email alerts. | `string` | `"ecipient@example.wazuh.com"` | no |
| es\_datanode\_storage\_size | Storage size for ES datanodes | `string` | `"50Gi"` | no |
| init\_container\_image | Default image for init container | `string` | `"busybox"` | no |
| kibana\_default\_image | Wazuh kibana default image | `string` | `"wazuh/wazuh-kibana-odfe:4.1.1"` | no |
| log\_format | Choose between "plain", "json", or "plain,json" for the format of internal logs | `string` | `"plain"` | no |
| opendistro\_default\_image | Opendistro base image | `string` | `"amazon/opendistro-for-elasticsearch:1.12.0"` | no |
| openscap\_disabled | Configuration options of the OpenSCAP wodle | `string` | `"yes"` | no |
| osquery\_disabled | Configuration options of the osquery wodle.Osquery is not installed by default. It is an open source software that you have to obtain for using this module. | `string` | `"yes"` | no |
| prefix | Wazuh naming convention | `string` | `"wazuh"` | no |
| queue\_size | This sets the size of the message input buffer in Analysisd (number of events). | `string` | `"131072"` | no |
| rootcheck\_disabled | Disables the execution of rootcheck | `string` | `"no"` | no |
| smtp\_server | This option defines what SMTP server to use to deliver alerts. | `string` | `"smtp.example.wazuh.com"` | no |
| storage\_class\_create | Create or Not Kubernetes storage class | `bool` | n/a | yes |
| storage\_provisioner | Kubernetes storage class for Wazuh for example kubernetes.io/gce-pd | `string` | `""` | no |
| storage\_provisioner\_type | Kubernetes Storage type. Need to setup only if storage\_class\_create is true | `string` | `""` | no |
| syscheck\_disabled | File integrity monitoring | `string` | `"no"` | no |
| syscollector\_disabled | Configuration options of the Syscollector wodle for system inventory. | `string` | `"no"` | no |
| vulnerability\_detector\_enabled | This section covers the configuration for the Vulnerability detection module. | `string` | `"no"` | no |
| wazuh\_agent\_default\_image | Wazuh agent image | `string` | `"kennyopennix/wazuh-agent:latest"` | no |
| wazuh\_agent\_enabled | Enable or disabled deploy of Wazuh agent DaemonSet | `bool` | `false` | no |
| wazuh\_default\_image | Wazuh manager default image | `string` | `"wazuh/wazuh-odfe:4.1.1"` | no |
| wazuh\_es\_cpu\_limit | Opendistro cpu limit | `string` | `"500m"` | no |
| wazuh\_es\_cpu\_request | Opendistro cpu request | `string` | `"100m"` | no |
| wazuh\_es\_memory\_limit | Opendistro memory limit | `string` | `"500Mi"` | no |
| wazuh\_es\_memory\_request | Opendistro memory request | `string` | `"100Mi"` | no |
| wazuh\_es\_repications | Opendistro stateful set replications set | `string` | `3` | no |
| wazuh\_manager\_cpu\_limit | Wazuh manager cpu limit | `string` | `"500m"` | no |
| wazuh\_manager\_cpu\_request | Wazuh manager cpu request | `string` | `"100m"` | no |
| wazuh\_manager\_memory\_limit | Wazuh manager memory limit | `string` | `"500Mi"` | no |
| wazuh\_manager\_memory\_request | Wazuh manager memory request | `string` | `"100Mi"` | no |
| wazuh\_manager\_storage\_size | Storage size of Wazuh manager | `string` | `"50Gi"` | no |
| wazuh\_manager\_worker\_replications | Wazuh worker replications count | `string` | `2` | no |
| wazuh\_namespace | Wazuh Kubernetes namespace | `string` | `"wazuh"` | no |
| wazuh\_storage\_class\_name | Kubernetes storage class name | `string` | n/a | yes |
| wazuh\_worker\_cpu\_limit | Wazuh worker cpu limit | `string` | `"1"` | no |
| wazuh\_worker\_cpu\_request | Wazuh worker cpu request | `string` | `"100m"` | no |
| wazuh\_worker\_memory\_limit | Wazuh worker memory limit | `string` | `"1000Mi"` | no |
| wazuh\_worker\_memory\_request | Wazuh worker memory request | `string` | `"100Mi"` | no |
| wazuh\_worker\_storage\_size | Storage size of Wazuh worker | `string` | `"50Gi"` | no |
| white\_lists | This specifies an IP for which Active Responses will not be triggered. Only one IP may be specified for each <while\_list> tag, but several IPs may be used by including multiple <white\_list> tags. | `list(string)` | `[]` | no |
| worker\_ciscat\_disabled | Configuration options of the CIS-CAT wodle. | `string` | `"yes"` | no |
| worker\_log\_format | Choose between "plain", "json", or "plain,json" for the format of internal logs | `string` | `"plain"` | no |
| worker\_openscap\_disabled | Configuration options of the OpenSCAP wodle | `string` | `"yes"` | no |
| worker\_osquery\_disabled | Configuration options of the osquery wodle.Osquery is not installed by default. It is an open source software that you have to obtain for using this module. | `string` | `"yes"` | no |
| worker\_queue\_size | This sets the size of the message input buffer in Analysisd (number of events). | `string` | `"131072"` | no |
| worker\_rootcheck\_disabled | Disables the execution of rootcheck | `string` | `"no"` | no |
| worker\_syscheck\_disabled | File integrity monitoring | `string` | `"no"` | no |
| worker\_syscollector\_disabled | Configuration options of the Syscollector wodle for system inventory. | `string` | `"no"` | no |
| worker\_vulnerability\_detector\_enabled | This section covers the configuration for the Vulnerability detection module. | `string` | `"no"` | no |
| worker\_white\_lists | This specifies an IP for which Active Responses will not be triggered. Only one IP may be specified for each <while\_list> tag, but several IPs may be used by including multiple <white\_list> tags. | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| admin\_password | Kibana admin password |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
