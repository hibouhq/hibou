locals {
  ssh_private_key_path = trimsuffix(var.ssh_public_key_path, ".pub")
}

output "server_ip" {
  description = "Public IPv4 address of the server"
  value       = scaleway_instance_ip.hibou.address
}

output "ssh_command" {
  description = "SSH command to connect to the server"
  value       = "ssh -i ${local.ssh_private_key_path} root@${scaleway_instance_ip.hibou.address}"
}

output "kubeconfig_command" {
  description = "Command to fetch kubeconfig from the server"
  value       = "scp -i ${local.ssh_private_key_path} root@${scaleway_instance_ip.hibou.address}:/etc/rancher/k3s/k3s.yaml ./kubeconfig.yaml && sed -i 's/127.0.0.1/${scaleway_instance_ip.hibou.address}/g' kubeconfig.yaml"
}
