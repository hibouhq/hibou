locals {
  ssh_public_key = file(pathexpand(var.ssh_public_key_path))
}

resource "scaleway_account_ssh_key" "hibou" {
  name       = "${var.server_name}-ssh"
  public_key = local.ssh_public_key
}

resource "scaleway_instance_security_group" "hibou" {
  name                    = "${var.server_name}-sg"
  inbound_default_policy  = "drop"
  outbound_default_policy = "accept"

  # Accept ICMP. Scaleway rules cannot filter by type, so this is all of IPv4
  # ICMP, not just the fragmentation-needed errors that path MTU discovery
  # depends on — dropping those turns an MTU mismatch into a hung TLS handshake
  # rather than a clean failure. Ping and traceroute come along with it.
  inbound_rule {
    action   = "accept"
    protocol = "ICMP"
  }

  dynamic "inbound_rule" {
    for_each = var.ssh_allowed_ips
    content {
      action   = "accept"
      protocol = "TCP"
      port     = 22
      ip_range = inbound_rule.value
    }
  }

  inbound_rule {
    action   = "accept"
    protocol = "TCP"
    port     = 80
  }

  inbound_rule {
    action   = "accept"
    protocol = "TCP"
    port     = 443
  }

  dynamic "inbound_rule" {
    for_each = var.enable_k8s_api_access ? var.ssh_allowed_ips : []
    content {
      action   = "accept"
      protocol = "TCP"
      port     = 6443
      ip_range = inbound_rule.value
    }
  }
}

resource "scaleway_instance_ip" "hibou" {}

resource "scaleway_instance_server" "hibou" {
  name              = var.server_name
  type              = var.instance_type
  image             = var.image
  ip_id             = scaleway_instance_ip.hibou.id
  security_group_id = scaleway_instance_security_group.hibou.id

  root_volume {
    size_in_gb = var.root_volume_size_gb
  }

  cloud_init = templatefile("${path.module}/cloud-init.yaml.tpl", {
    enable_k8s_api_access = var.enable_k8s_api_access
    k3s_version           = var.k3s_version
    server_name           = var.server_name
  })
}
