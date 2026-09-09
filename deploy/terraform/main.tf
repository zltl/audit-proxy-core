terraform {
  required_version = ">= 1.0"
}

variable "proxy_server" {
  description = "Audit Proxy control plane address"
  type        = string
  default     = "https://proxy.example.com:8443"
}

variable "proxy_token" {
  description = "API token for Audit Proxy control plane"
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
      })}' | terraform-provider-audit-proxy create-user
    EOT

    environment = {
      AUDITPROXY_SERVER = var.proxy_server
      AUDITPROXY_TOKEN  = var.proxy_token
    }
  }

  provisioner "local-exec" {
    when    = destroy
    command = "terraform-provider-audit-proxy delete-user ${self.triggers.username}"

    environment = {
      AUDITPROXY_SERVER = self.triggers.proxy_server
      AUDITPROXY_TOKEN  = self.triggers.proxy_token
    }
  }
}

# ---------- Servers ----------

# Read current server list via the external data source pattern.
data "external" "servers" {
  program = ["terraform-provider-audit-proxy", "read-servers"]

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
