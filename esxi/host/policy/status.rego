package main

deny_InMaintenanceMode[msg] {
  host := input.HostSystems[0]
  host.Runtime.InMaintenanceMode == true
  msg := "Host is not InMaintenanceMode."
}

