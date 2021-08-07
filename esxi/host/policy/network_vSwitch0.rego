package main

deny_host_vSwitch_MTU[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch[_]
  vswitch.Name == "vSwitch0"
  vswitch.Mtu != 1500

  msg := sprintf("%s is misconfigration. MTU should be set 1500.", [vswitch.Name])
}

deny_host_vSwitch_Portgroup[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch[_]
  vswitch.Name == "vSwitch0"
  count(vswitch.Portgroup)  == 2
  vswitch.Portgroup[i] != "key-vim.host.PortGroup-VM Network"
  vswitch.Portgroup[i] != "key-vim.host.PortGroup-Management Network"

  msg := sprintf("%s is misconfigration. Portgroup should be set.", [vswitch.Name])
}

deny_host_vSwitch_PNIC[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch[_]
  vswitch.Name == "vSwitch0"
  count(vswitch.Pnic)  == 1
  vswitch.Pnic[0] != "key-vim.host.PhysicalNic-vmnic0"

  msg := sprintf("%s is misconfigration. PNIC should be set vmnic0.", [vswitch.Name])
}

deny_host_vSwitch_secutiry[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch[_]
  vswitch.Name == "vSwitch0"
  vswitch.Spec.Policy.Security.AllowPromiscuous != false

  msg := sprintf("%s is misconfigration. Security should be set.", [vswitch.Name])
}

deny_host_vSwitch_secutiry[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch[_]
  vswitch.Name == "vSwitch0"
  vswitch.Spec.Policy.Security.MacChanges != true

  msg := sprintf("%s is misconfigration. Security should be set.", [vswitch.Name])
}

deny_host_vSwitch_secutiry[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch[_]
  vswitch.Name == "vSwitch0"
  vswitch.Spec.Policy.Security.ForgedTransmits != true

  msg := sprintf("%s is misconfigration. Security should be set.", [vswitch.Name])
}

deny_host_vSwitch_nicteaming[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch[_]
  vswitch.Name == "vSwitch0"
  vswitch.Spec.Policy.NicTeaming.Policy != "loadbalance_srcid"

  msg := sprintf("%s is misconfigration. NicTeaming should be set.", [vswitch.Name])
}

deny_host_vSwitch_nicteaming[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch[_]
  vswitch.Name == "vSwitch0"
  vswitch.Spec.Policy.NicTeaming.ReversePolicy != true

  msg := sprintf("%s is misconfigration. NicTeaming should be set.", [vswitch.Name])
}

deny_host_vSwitch_nicteaming[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch[_]
  vswitch.Name == "vSwitch0"
  vswitch.Spec.Policy.NicTeaming.NotifySwitches != true

  msg := sprintf("%s is misconfigration. NicTeaming should be set.", [vswitch.Name])
}

# RollingOrder
# true  : not failback
# false : failback
deny_host_vSwitch_nicteaming[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch[_]
  vswitch.Name == "vSwitch0"
  vswitch.Spec.Policy.NicTeaming.RollingOrder != false

  msg := sprintf("%s is misconfigration. NicTeaming should be set.", [vswitch.Name])
}

deny_host_vSwitch_nicteaming[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch[_]
  vswitch.Name == "vSwitch0"
  vswitch.Spec.Policy.NicTeaming.NicOrder.ActiveNic[_] != "vmnic0"

  msg := sprintf("%s is misconfigration. NicTeaming should be set.", [vswitch.Name])
}

deny_host_vSwitch_nicteaming[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch[_]
  vswitch.Name == "vSwitch0"
  vswitch.Spec.Policy.NicTeaming.NicOrder.StandbyNic != null

  msg := sprintf("%s is misconfigration. NicTeaming should be set.", [vswitch.Name])
}

