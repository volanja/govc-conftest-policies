package main

deny_host_Pnic_vmnic_LinkSpeed[msg] {
  pnic := input.HostSystems[0].Config.Network.Pnic[_]
  pnic.Device == "vmnic0"
  pnic.LinkSpeed.SpeedMb != 1000

  msg := sprintf("%s is misconfigration. LinkSpped should be set 1000 Mbps.", [pnic.Device])
}

deny_host_Pnic_vmnic_Duplex[msg] {
  pnic := input.HostSystems[0].Config.Network.Pnic[_]
  pnic.Device == "vmnic0"
  pnic.LinkSpeed.Duplex != true

  msg := sprintf("%s is misconfigration. Duplex should be set true.", [pnic.Device])
}

deny_host_Pnic_vmnic_Driver[msg] {
  pnic := input.HostSystems[0].Config.Network.Pnic[_]
  pnic.Device == "vmnic0"
  pnic.Driver != "e1000"

  msg := sprintf("%s is misconfigration. Driver should be set e1000.", [pnic.Device])
}

# see https://kb.vmware.com/s/article/1031111
deny_host_Pnic_vmnic_Mac[msg] {
  pnic := input.HostSystems[0].Config.Network.Pnic[_]
  pnic.Device == "vmnic0"
  pnic.Mac != "08:00:27:26:01:f9"

  msg := sprintf("%s is misconfigration. MacAddress should be set 08:00:27:26:01:f9.", [pnic.Device])
}
