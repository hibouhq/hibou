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

  cloud_init = templatefile("${path.module}/cloud-init.yaml.tpl", {
    enable_k8s_api_access = var.enable_k8s_api_access
    k3s_version           = var.k3s_version
    server_name           = var.server_name
  })
}
