#cloud-config
package_update: true
package_upgrade: true

packages:
  - fail2ban
  - ufw
  - unattended-upgrades
  - apt-listchanges

write_files:
  - path: /etc/ssh/sshd_config.d/99-hardening.conf
    content: |
      PasswordAuthentication no
      PermitRootLogin prohibit-password
      X11Forwarding no
      MaxAuthTries 3

  - path: /etc/fail2ban/jail.local
    content: |
      [sshd]
      enabled = true
      port = ssh
      maxretry = 3
      bantime = 3600

runcmd:
  # Scaleway Security Group is primary network-level control. UFW remains defense in depth on-host.
  - ufw default deny incoming
  - ufw default allow outgoing
  - ufw allow 22/tcp
  - ufw allow 80/tcp
  - ufw allow 443/tcp
%{ if enable_k8s_api_access ~}
  - ufw allow 6443/tcp
%{ endif ~}
  - ufw --force enable
  - |
      # Download installer first; TLS secures transport while INSTALL_K3S_VERSION pins installed binary version.
      curl -sfL https://get.k3s.io -o /tmp/k3s-install.sh
      test -s /tmp/k3s-install.sh
      chmod +x /tmp/k3s-install.sh
      INSTALL_K3S_VERSION="${k3s_version}" /tmp/k3s-install.sh server \
        --tls-san $(curl -sf http://169.254.169.254/latest/meta-data/public-ipv4) \
        --node-name "${server_name}" \
        --write-kubeconfig-mode 644
      k3s --version | grep -F "${k3s_version}"
      rm -f /tmp/k3s-install.sh
  - systemctl enable --now fail2ban
  - systemctl restart sshd
