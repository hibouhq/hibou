locals {
  ssh_public_key = file(pathexpand(var.ssh_public_key_path))
}

resource "hcloud_ssh_key" "hibou" {
  name       = "${var.server_name}-ssh"
  public_key = local.ssh_public_key
}

resource "hcloud_firewall" "hibou" {
  name = "${var.server_name}-firewall"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = var.ssh_allowed_ips
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "80"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  dynamic "rule" {
    for_each = var.enable_k8s_api_access ? [1] : []
    content {
      direction  = "in"
      protocol   = "tcp"
      port       = "6443"
      source_ips = var.ssh_allowed_ips
    }
  }
}

resource "hcloud_server" "hibou" {
  name        = var.server_name
  server_type = var.server_type
  location    = var.location
  image       = var.image
  ssh_keys    = [hcloud_ssh_key.hibou.id]
  firewall_ids = [hcloud_firewall.hibou.id]

  user_data = templatefile("${path.module}/cloud-init.yaml.tpl", {
    enable_k8s_api_access = var.enable_k8s_api_access
    k3s_version           = var.k3s_version
    server_name           = var.server_name
  })
}
