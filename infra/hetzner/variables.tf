variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "server_name" {
  description = "Name for the Hetzner server"
  type        = string
  default     = "hibou"
}

variable "server_type" {
  description = "Hetzner server type"
  type        = string
  default     = "cax11"
}

variable "location" {
  description = "Hetzner location"
  type        = string
  default     = "fsn1"
}

variable "image" {
  description = "Base server image"
  type        = string
  default     = "ubuntu-24.04"
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key uploaded to Hetzner"
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "k3s_version" {
  description = "k3s version installed by cloud-init"
  type        = string
  default     = "v1.31.4+k3s1"
}

variable "enable_k8s_api_access" {
  description = "Whether to open TCP 6443 for remote Kubernetes API access"
  type        = bool
  default     = false
}

variable "ssh_allowed_ips" {
  description = "CIDRs allowed to access SSH and optional Kubernetes API. Restrict this to trusted source ranges instead of leaving it open to the Internet."
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]

  validation {
    condition = !contains(var.ssh_allowed_ips, "0.0.0.0/0") || !contains(var.ssh_allowed_ips, "::/0")
    error_message = "Avoid leaving both IPv4 and IPv6 open. Restrict ssh_allowed_ips to trusted CIDRs whenever possible."
  }
}
