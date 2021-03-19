output "admin_password" {
  value       = random_password.this.result
  description = "Kibana admin password"
}
