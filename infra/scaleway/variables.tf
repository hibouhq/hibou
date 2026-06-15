variable "scw_access_key" {
  description = "Scaleway API access key"
  type        = string
  sensitive   = true
}

variable "scw_secret_key" {
  description = "Scaleway API secret key"
  type        = string
  sensitive   = true
}

variable "scw_project_id" {
  description = "Scaleway project ID"
  type        = string
}

variable "server_name" {
  description = "Name for the Scaleway server"
  type        = string
  default     = "hibou"
}

variable "instance_type" {
  description = "Scaleway instance type"
  type        = string
  default     = "DEV1-M"
}

variable "zone" {
  description = "Scaleway availability zone"
  type        = string
  default     = "fr-par-1"
}

variable "image" {
  description = "Base server image slug"
  type        = string
  default     = "ubuntu_noble"
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key uploaded to Scaleway"
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
    condition     = !contains(var.ssh_allowed_ips, "0.0.0.0/0") || !contains(var.ssh_allowed_ips, "::/0")
    error_message = "Avoid leaving both IPv4 and IPv6 open. Restrict ssh_allowed_ips to trusted CIDRs whenever possible."
  }
}
