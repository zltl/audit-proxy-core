# Reusable module for managing SSH Proxy users via the Terraform provider CLI.
#
# Usage:
#   module "my_user" {
#     source       = "./modules/user"
#     proxy_server = "https://proxy.example.com:8443"
#     proxy_token  = var.token
#     username     = "alice"
#     display_name = "Alice"
#     role         = "operator"
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

variable "username" {
  description = "Username to create"
  type        = string
}

variable "display_name" {
  description = "User display name"
  type        = string
  default     = ""
}

variable "role" {
  description = "User role (admin, operator, viewer)"
  type        = string
  default     = "viewer"

  validation {
    condition     = contains(["admin", "operator", "viewer"], var.role)
    error_message = "Role must be one of: admin, operator, viewer."
  }
}

variable "password" {
  description = "Initial password"
  type        = string
  default     = "changeme"
  sensitive   = true
}

resource "null_resource" "user" {
  triggers = {
    username     = var.username
    role         = var.role
    display_name = var.display_name
    proxy_server = var.proxy_server
    proxy_token  = var.proxy_token
  }

  provisioner "local-exec" {
    command = <<-EOT
      echo '${jsonencode({
        username     = var.username,
        display_name = var.display_name,
        role         = var.role,
        password     = var.password
      })}' | terraform-provider-sshproxy create-user
    EOT

    environment = {
      SSHPROXY_SERVER = var.proxy_server
      SSHPROXY_TOKEN  = var.proxy_token
    }
  }

  provisioner "local-exec" {
    when    = destroy
    command = "terraform-provider-sshproxy delete-user ${self.triggers.username}"

    environment = {
      SSHPROXY_SERVER = self.triggers.proxy_server
      SSHPROXY_TOKEN  = self.triggers.proxy_token
    }
  }
}

output "username" {
  description = "The created username"
  value       = var.username
}
