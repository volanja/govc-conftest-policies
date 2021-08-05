package main

deny_host_Portgroup_VM_Network_vlan[msg] {
  portgroup := input.HostSystems[0].Config.Network.Portgroup[0]
  portgroup.Spec.Name == "VM Network"
  portgroup.Spec.VlanId != 0

  msg := "VM Network is misconfigration. VLAN ID should be set 0."
}
