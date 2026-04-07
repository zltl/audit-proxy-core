variable "proxy_server" {
  description = "SSH Proxy control-plane base URL"
  type        = string
}

variable "proxy_token" {
  description = "API authentication token"
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
