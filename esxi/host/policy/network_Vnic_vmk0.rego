package main

deny_host_Vnic_vmk0_Portgroup[msg] {
  vnic := input.HostSystems[0].Config.Network.Vnic[_]
  vnic.Device == "vmk0"
  vnic.Portgroup != "Management Network"

  msg := sprintf("%s is misconfigration. Portgroup should be set Management Network.", [vnic.Device])
}

deny_host_Vnic_vmk0_dhcp_enable[msg] {
  vnic := input.HostSystems[0].Config.Network.Vnic[_]
  vnic.Device == "vmk0"
  vnic.Spec.Ip.Dhcp == true

  msg := sprintf("%s is misconfigration. DHCP should be set disabled.", [vnic.Device])
}

deny_host_Vnic_vmk0_IPAddress[msg] {
  vnic := input.HostSystems[0].Config.Network.Vnic[_]
  vnic.Device == "vmk0"
  vnic.Spec.Ip.IpAddress != "192.168.100.120"

  msg := sprintf("%s is misconfigration. IPAddress should be set 192.168.100.120.", [vnic.Device])
}

deny_host_Vnic_vmk0_SubnetMask[msg] {
  vnic := input.HostSystems[0].Config.Network.Vnic[_]
  vnic.Device == "vmk0"
  vnic.Spec.Ip.SubnetMask != "255.255.255.0"

  msg := sprintf("%s is misconfigration. SubnetMask should be set 255.255.255.0.", [vnic.Device])
}

# see https://kb.vmware.com/s/article/1031111
deny_host_Vnic_vmk0_Mac[msg] {
  vnic := input.HostSystems[0].Config.Network.Vnic[_]
  vnic.Device == "vmk0"
  vnic.Spec.Mac != "08:00:27:26:01:f9"

  msg := sprintf("%s is misconfigration. MacAddress should be set 08:00:27:26:01:f9.", [vnic.Device])
}

deny_host_Vnic_vmk0_Mtu[msg] {
  vnic := input.HostSystems[0].Config.Network.Vnic[_]
  vnic.Device == "vmk0"
  vnic.Spec.Mtu != 1500

  msg := sprintf("%s is misconfigration. MTU should be set 1500.", [vnic.Device])
}
