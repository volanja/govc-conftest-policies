package main

deny_service_ntpd[msg] {
  service := input.HostSystems[0].Config.Service.Service[_]
  service.Key == "ntpd"
  service.Running == false
  msg := "Service NTPD should be running."
}

deny_service_ntpd[msg] {
  service := input.HostSystems[0].Config.Service.Service[_]
  service.Key == "ntpd"
  service.Policy  == "off"
  msg := "Service NTPD should be running."
}

deny_firewall_ntpd[msg] {
  ruleset := input.HostSystems[0].Config.Firewall.Ruleset[_]
  ruleset.Key == "ntpClient"
  ruleset.Service == "ntpd"
  ruleset.Enabled == false
  msg := "Firewall NTPD should be enabled."
}

deny_config_ntpd[msg] {
  ntpconfig := input.HostSystems[0].Config.DateTimeInfo.NtpConfig
  ntpconfig.Server == null
  msg := "NTPD should be configured."
}

deny_config_ntpd[msg] {
  ntpconfig := input.HostSystems[0].Config.DateTimeInfo.NtpConfig
  ntpconfig.Server[_] != "192.168.100.1"
  msg := "NTPD should be configured."
}
