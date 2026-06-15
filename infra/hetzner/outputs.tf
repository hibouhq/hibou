locals {
  ssh_private_key_path = trimsuffix(var.ssh_public_key_path, ".pub")
}

output "server_ip" {
  description = "Public IPv4 address of the server"
  value       = hcloud_server.hibou.ipv4_address
}

output "ssh_command" {
  description = "SSH command to connect to the server"
  value       = "ssh -i ${local.ssh_private_key_path} root@${hcloud_server.hibou.ipv4_address}"
}

output "kubeconfig_command" {
  description = "Command to fetch kubeconfig from the server"
  value       = "scp -i ${local.ssh_private_key_path} root@${hcloud_server.hibou.ipv4_address}:/etc/rancher/k3s/k3s.yaml ./kubeconfig.yaml && sed -i 's/127.0.0.1/${hcloud_server.hibou.ipv4_address}/g' kubeconfig.yaml"
}
