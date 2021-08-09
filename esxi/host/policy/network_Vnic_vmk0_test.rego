package main

test_correct_vmk0_Portgroup {
  msg := "vmk0 is misconfigration. Portgroup should be set Management Network."
  not deny_host_Vnic_vmk0_Portgroup[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vnic": [
            {
              "Device": "vmk0",
              "Key": "key-vim.host.VirtualNic-vmk0",
              "Portgroup": "Management Network",
              "Spec": {
                "Ip": {
                  "Dhcp": false,
                  "IpAddress": "192.168.100.120",
                  "SubnetMask": "255.255.255.0",
                },
                "Mac": "08:00:27:26:01:f9",
                "DistributedVirtualPort": null,
                "Portgroup": "Management Network",
                "Mtu": 1500,
                "TsoEnabled": true,
                "NetStackInstanceKey": "defaultTcpipStack",
                "OpaqueNetwork": null,
                "ExternalId": "",
                "PinnedPnic": "",
                "IpRouteSpec": null,
                "SystemOwned": null
              },
              "Port": "key-vim.host.PortGroup.Port-33554436"
            }]}}}]
  }
}

test_incorrect_vmk0_Portgroup {
  msg := "vmk0 is misconfigration. Portgroup should be set Management Network."
  deny_host_Vnic_vmk0_Portgroup[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vnic": [
            {
              "Device": "vmk0",
              "Key": "key-vim.host.VirtualNic-vmk0",
              "Portgroup": "VM Network",
              "Spec": {
                "Ip": {
                  "Dhcp": false,
                  "IpAddress": "192.168.100.120",
                  "SubnetMask": "255.255.255.0",
                },
                "Mac": "08:00:27:26:01:f9",
                "DistributedVirtualPort": null,
                "Portgroup": "Management Network",
                "Mtu": 1500,
                "TsoEnabled": true,
                "NetStackInstanceKey": "defaultTcpipStack",
                "OpaqueNetwork": null,
                "ExternalId": "",
                "PinnedPnic": "",
                "IpRouteSpec": null,
                "SystemOwned": null
              },
              "Port": "key-vim.host.PortGroup.Port-33554436"
            }]}}}]
  }
}

test_correct_vmk0_DHCP {
  msg := "vmk0 is misconfigration. DHCP should be set disabled."
  not deny_host_Vnic_vmk0_dhcp_enable[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vnic": [
            {
              "Device": "vmk0",
              "Key": "key-vim.host.VirtualNic-vmk0",
              "Portgroup": "Management Network",
              "Spec": {
                "Ip": {
                  "Dhcp": false,
                  "IpAddress": "192.168.100.120",
                  "SubnetMask": "255.255.255.0",
                },
              },
              "Port": "key-vim.host.PortGroup.Port-33554436"
            }]}}}]
  }
}

test_incorrect_vmk0_DHCP {
  msg := "vmk0 is misconfigration. DHCP should be set disabled."
  deny_host_Vnic_vmk0_dhcp_enable[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vnic": [
            {
              "Device": "vmk0",
              "Key": "key-vim.host.VirtualNic-vmk0",
              "Portgroup": "Management Network",
              "Spec": {
                "Ip": {
                  "Dhcp": true
                },
              },
              "Port": "key-vim.host.PortGroup.Port-33554436"
            }]}}}]
  }
}

test_correct_vmk0_IPAddress {
  msg := "vmk0 is misconfigration. IPAddress should be set 192.168.100.120."
  not deny_host_Vnic_vmk0_IPAddress[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vnic": [
            {
              "Device": "vmk0",
              "Key": "key-vim.host.VirtualNic-vmk0",
              "Portgroup": "Management Network",
              "Spec": {
                "Ip": {
                  "Dhcp": false,
                  "IpAddress": "192.168.100.120",
                  "SubnetMask": "255.255.255.0",
                },
                "Mac": "08:00:27:26:01:f9",
              },
              "Port": "key-vim.host.PortGroup.Port-33554436"
            }]}}}]
  }
}

test_incorrect_vmk0_IPAddress {
  msg := "vmk0 is misconfigration. IPAddress should be set 192.168.100.120."
  deny_host_Vnic_vmk0_IPAddress[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vnic": [
            {
              "Device": "vmk0",
              "Key": "key-vim.host.VirtualNic-vmk0",
              "Portgroup": "Management Network",
              "Spec": {
                "Ip": {
                  "Dhcp": false,
                  "IpAddress": "192.168.100.121",
                  "SubnetMask": "255.255.255.0",
                },
                "Mac": "08:00:27:26:01:f9",
              },
              "Port": "key-vim.host.PortGroup.Port-33554436"
            }]}}}]
  }
}

test_correct_vmk0_SubnetMask {
  msg := "vmk0 is misconfigration. SubnetMask should be set 255.255.255.0."
  not deny_host_Vnic_vmk0_SubnetMask[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vnic": [
            {
              "Device": "vmk0",
              "Key": "key-vim.host.VirtualNic-vmk0",
              "Portgroup": "Management Network",
              "Spec": {
                "Ip": {
                  "Dhcp": false,
                  "IpAddress": "192.168.100.120",
                  "SubnetMask": "255.255.255.0",
                },
              },
              "Port": "key-vim.host.PortGroup.Port-33554436"
            }]}}}]
  }
}

test_incorrect_vmk0_SubnetMask {
  msg := "vmk0 is misconfigration. SubnetMask should be set 255.255.255.0."
  deny_host_Vnic_vmk0_SubnetMask[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vnic": [
            {
              "Device": "vmk0",
              "Key": "key-vim.host.VirtualNic-vmk0",
              "Portgroup": "Management Network",
              "Spec": {
                "Ip": {
                  "Dhcp": false,
                  "IpAddress": "192.168.100.120",
                  "SubnetMask": "255.0.0.0",
                },
              },
              "Port": "key-vim.host.PortGroup.Port-33554436"
            }]}}}]
  }
}

test_correct_vmk0_Mac {
  msg := "vmk0 is misconfigration. MacAddress should be set 08:00:27:26:01:f9."
  not deny_host_Vnic_vmk0_Mac[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vnic": [
            {
              "Device": "vmk0",
              "Key": "key-vim.host.VirtualNic-vmk0",
              "Portgroup": "Management Network",
              "Spec": {
                "Ip": {
                  "Dhcp": false,
                  "IpAddress": "192.168.100.120",
                  "SubnetMask": "255.255.255.0",
                },
                "Mac": "08:00:27:26:01:f9",
              },
              "Port": "key-vim.host.PortGroup.Port-33554436"
            }]}}}]
  }
}

test_incorrect_vmk0_Mac {
  msg := "vmk0 is misconfigration. MacAddress should be set 08:00:27:26:01:f9."
  deny_host_Vnic_vmk0_Mac[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vnic": [
            {
              "Device": "vmk0",
              "Key": "key-vim.host.VirtualNic-vmk0",
              "Portgroup": "Management Network",
              "Spec": {
                "Ip": {
                  "Dhcp": false,
                  "IpAddress": "192.168.100.120",
                  "SubnetMask": "255.255.255.0",
                },
                "Mac": "11:22:33:44:55:66",
              },
              "Port": "key-vim.host.PortGroup.Port-33554436"
            }]}}}]
  }
}

test_correct_vmk0_Mtu {
  msg := "vmk0 is misconfigration. MTU should be set 1500."
  not deny_host_Vnic_vmk0_Mtu[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vnic": [
            {
              "Device": "vmk0",
              "Key": "key-vim.host.VirtualNic-vmk0",
              "Portgroup": "Management Network",
              "Spec": {
                "Ip": {
                  "Dhcp": false,
                  "IpAddress": "192.168.100.120",
                  "SubnetMask": "255.255.255.0",
                },
                "Mac": "08:00:27:26:01:f9",
                "DistributedVirtualPort": null,
                "Portgroup": "Management Network",
                "Mtu": 1500,
              },
              "Port": "key-vim.host.PortGroup.Port-33554436"
            }]}}}]
  }
}

test_incorrect_vmk0_Mtu {
  msg := "vmk0 is misconfigration. MTU should be set 1500."
  deny_host_Vnic_vmk0_Mtu[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vnic": [
            {
              "Device": "vmk0",
              "Key": "key-vim.host.VirtualNic-vmk0",
              "Portgroup": "Management Network",
              "Spec": {
                "Ip": {
                  "Dhcp": false,
                  "IpAddress": "192.168.100.120",
                  "SubnetMask": "255.255.255.0",
                },
                "Mac": "08:00:27:26:01:f9",
                "DistributedVirtualPort": null,
                "Portgroup": "Management Network",
                "Mtu": 9000,
              },
              "Port": "key-vim.host.PortGroup.Port-33554436"
            }]}}}]
  }
}

