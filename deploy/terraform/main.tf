terraform {
  required_version = ">= 1.0"
}

variable "proxy_server" {
  description = "SSH Proxy control plane address"
  type        = string
  default     = "https://proxy.example.com:8443"
}

variable "proxy_token" {
  description = "API token for SSH Proxy control plane"
  type        = string
  sensitive   = true
}

variable "admin_username" {
  description = "Admin user to create"
  type        = string
  default     = "admin"
}

variable "admin_display_name" {
  description = "Display name for the admin user"
  type        = string
  default     = "Administrator"
}

# ---------- Users ----------

# Create an admin user via the Terraform provider CLI.
resource "null_resource" "user_admin" {
  triggers = {
    username     = var.admin_username
    role         = "admin"
    display_name = var.admin_display_name
  }

  provisioner "local-exec" {
    command = <<-EOT
      echo '${jsonencode({
        username     = var.admin_username,
        role         = "admin",
        display_name = var.admin_display_name,
        password     = "changeme"
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

# ---------- Servers ----------

# Read current server list via the external data source pattern.
data "external" "servers" {
  program = ["terraform-provider-sshproxy", "read-servers"]

  query = {}
}

# ---------- Modules ----------

module "operator_user" {
  source = "./modules/user"

  proxy_server = var.proxy_server
  proxy_token  = var.proxy_token
  username     = "operator"
  display_name = "Operator"
  role         = "operator"
}

module "app_server" {
  source = "./modules/server"

  proxy_server = var.proxy_server
  proxy_token  = var.proxy_token
  name         = "app-server-1"
  host         = "10.0.1.10"
  port         = 22
  group        = "application"
}
