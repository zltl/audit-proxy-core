# Reusable module for managing SSH Proxy upstream servers via the Terraform
# provider CLI.
#
# Usage:
#   module "my_server" {
#     source       = "./modules/server"
#     proxy_server = "https://proxy.example.com:8443"
#     proxy_token  = var.token
#     name         = "web-1"
#     host         = "10.0.1.5"
#     port         = 22
#     group        = "web"
#   }

terraform {
  required_version = ">= 1.0"
}

variable "proxy_server" {
  description = "SSH Proxy control-plane base URL"
  type        = string
}

variable "proxy_token" {
  description = "API authentication token"
  type        = string
  sensitive   = true
}

variable "name" {
  description = "Server display name"
  type        = string
}

variable "host" {
  description = "Server hostname or IP"
  type        = string
}

variable "port" {
  description = "SSH port"
  type        = number
  default     = 22
}

variable "group" {
  description = "Server group"
  type        = string
  default     = "default"
}

variable "weight" {
  description = "Load-balancing weight"
  type        = number
  default     = 1
}

variable "max_sessions" {
  description = "Maximum concurrent sessions"
  type        = number
  default     = 0
}

variable "tags" {
  description = "Key-value tags"
  type        = map(string)
  default     = {}
}

resource "null_resource" "server" {
  triggers = {
    name         = var.name
    host         = var.host
    port         = tostring(var.port)
    group        = var.group
    proxy_server = var.proxy_server
    proxy_token  = var.proxy_token
  }

  provisioner "local-exec" {
    command = <<-EOT
      echo '${jsonencode({
        name         = var.name,
        host         = var.host,
        port         = var.port,
        group        = var.group,
        weight       = var.weight,
        max_sessions = var.max_sessions,
        tags         = var.tags
      })}' | terraform-provider-sshproxy create-server
    EOT

    environment = {
      SSHPROXY_SERVER = var.proxy_server
      SSHPROXY_TOKEN  = var.proxy_token
    }
  }

  provisioner "local-exec" {
    when    = destroy
    command = "echo 'Server ${self.triggers.name} (${self.triggers.host}:${self.triggers.port}) would be removed'"
  }
}

output "server_name" {
  description = "The created server name"
  value       = var.name
}

output "server_address" {
  description = "The server host:port"
  value       = "${var.host}:${var.port}"
}
