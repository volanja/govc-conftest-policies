package main

deny_host_Portgroup_VM_Network_vlan[msg] {
  portgroup := input.HostSystems[0].Config.Network.Portgroup[0]
  portgroup.Spec.Name == "VM Network"
  portgroup.Spec.VlanId != 0

  msg := sprintf("%s is misconfigration. VLAN ID should be set 0.", [portgroup.Spec.Name])
}

deny_host_Portgroup_VM_Network_vSwitch[msg] {
  portgroup := input.HostSystems[0].Config.Network.Portgroup[0]
  portgroup.Spec.Name == "VM Network"
  portgroup.Spec.VswitchName != "vSwitch0"

  msg := sprintf("%s is misconfigration. vSwitch should be set vSwitch0.", [portgroup.Spec.Name])
}
