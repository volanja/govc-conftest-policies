package main

deny_host_name[msg] {
  host := input.HostSystems[0]
  host.Name != "localhost.localdomain"
  msg := "Host name should be set."
}

deny_host_domain[msg] {
  host := input.HostSystems[0]
  not endswith(host.Name, ".localdomain")
  msg := "Host domain should be .localdomain"
}
