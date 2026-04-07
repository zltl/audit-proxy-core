output "admin_username" {
  description = "The admin username that was created"
  value       = var.admin_username
}

output "server_data" {
  description = "Server information from the SSH Proxy control plane"
  value       = data.external.servers.result
}

output "operator_user" {
  description = "Operator user module output"
  value       = module.operator_user.username
}

output "app_server" {
  description = "Application server module output"
  value       = module.app_server.server_name
}
