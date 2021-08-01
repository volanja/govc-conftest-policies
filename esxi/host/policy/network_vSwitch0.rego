package main

deny_host_vSwitch0_common[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch
  vswitch[0].Name == "vSwitch0"
  vswitch[0].Mtu != 1500

  msg := "vSwitch0 is misconfigration. MTU should be set 1500."
}

deny_host_vSwitch0_common[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch
  vswitch[0].Name == "vSwitch0"
  vswitch[0].Pnic[0] != "key-vim.host.PhysicalNic-vmnic0"

  msg := "vSwitch0 is misconfigration. PNIC should be set vmnic0."
}

deny_host_vSwitch0_secutiry[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch
  vswitch[0].Name == "vSwitch0"
  vswitch[0].Spec.Policy.Security.AllowPromiscuous != false

  msg := "vSwitch0 is misconfigration. Security should be set."
}

deny_host_vSwitch0_secutiry[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch
  vswitch[0].Name == "vSwitch0"
  vswitch[0].Spec.Policy.Security.MacChanges != true

  msg := "vSwitch0 is misconfigration. Security should be set."
}

deny_host_vSwitch0_secutiry[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch
  vswitch[0].Name == "vSwitch0"
  vswitch[0].Spec.Policy.Security.ForgedTransmits != true

  msg := "vSwitch0 is misconfigration. Security should be set."
}

deny_host_vSwitch0_nicteaming[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch
  vswitch[0].Name == "vSwitch0"
  vswitch[0].Spec.Policy.NicTeaming.Policy != "loadbalance_srcid"

  msg := "vSwitch0 is misconfigration. NicTeaming should be set."
}

deny_host_vSwitch0_nicteaming[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch
  vswitch[0].Name == "vSwitch0"
  vswitch[0].Spec.Policy.NicTeaming.ReversePolicy != true

  msg := "vSwitch0 is misconfigration. NicTeaming should be set."
}

deny_host_vSwitch0_nicteaming[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch
  vswitch[0].Name == "vSwitch0"
  vswitch[0].Spec.Policy.NicTeaming.NotifySwitches != true

  msg := "vSwitch0 is misconfigration. NicTeaming should be set."
}

# RollingOrder
# true  : not failback
# false : failback
deny_host_vSwitch0_nicteaming[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch
  vswitch[0].Name == "vSwitch0"
  vswitch[0].Spec.Policy.NicTeaming.RollingOrder != false

  msg := "vSwitch0 is misconfigration. NicTeaming should be set."
}

deny_host_vSwitch0_nicteaming[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch
  vswitch[0].Name == "vSwitch0"
  vswitch[0].Spec.Policy.NicTeaming.NicOrder.ActiveNic[_] != "vmnic0"

  msg := "vSwitch0 is misconfigration. NicTeaming should be set."
}

deny_host_vSwitch0_nicteaming[msg] {
  vswitch := input.HostSystems[0].Config.Network.Vswitch
  vswitch[0].Name == "vSwitch0"
  vswitch[0].Spec.Policy.NicTeaming.NicOrder.StandbyNic != null

  msg := "vSwitch0 is misconfigration. NicTeaming should be set."
}

