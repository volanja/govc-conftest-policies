package main

test_service_ntpd_running {
  msg := "Service NTPD should be running."
  not deny_service_ntpd[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Service": {
          "Service": [
          {
            "Key": "ntpd",
            "Label": "NTP Daemon",
            "Required": false,
            "Uninstallable": false,
            "Running": true,
            "Ruleset": [
              "ntpClient"
            ],
            "Policy": "on",
            "SourcePackage": {
              "SourcePackageName": "esx-base",
              "Description": "This VIB contains all of the base functionality of vSphere ESXi."
            }}]}}}]}
}

test_service_ntpd_stopped {
  msg := "Service NTPD should be running."
  deny_service_ntpd[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Service": {
          "Service": [
          {
            "Key": "ntpd",
            "Label": "NTP Daemon",
            "Required": false,
            "Uninstallable": false,
            "Running": false,
            "Ruleset": [
              "ntpClient"
            ],
            "Policy": "off",
            "SourcePackage": {
              "SourcePackageName": "esx-base",
              "Description": "This VIB contains all of the base functionality of vSphere ESXi."
            }}]}}}]}
}

test_firewall_ntpd_enabled {
  msg := "Firewall NTPD should be enabled."
  not deny_firewall_ntpd[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Firewall": {
          "Ruleset": [
          {
            "Key": "ntpClient",
            "Label": "NTP Client",
            "Required": false,
            "Rule": [
              {
                "Port": 123,
                "EndPort": 0,
                "Direction": "outbound",
                "PortType": "dst",
                "Protocol": "udp"
              }
            ],
            "Service": "ntpd",
            "Enabled": true,
            "AllowedHosts": {
              "IpAddress": null,
              "IpNetwork": null,
              "AllIp": true
            }
          }]}}}]}
}

test_firewall_ntpd_disabled {
  msg := "Firewall NTPD should be enabled."
  deny_firewall_ntpd[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Firewall": {
          "Ruleset": [
          {
            "Key": "ntpClient",
            "Label": "NTP Client",
            "Required": false,
            "Rule": [
              {
                "Port": 123,
                "EndPort": 0,
                "Direction": "outbound",
                "PortType": "dst",
                "Protocol": "udp"
              }
            ],
            "Service": "ntpd",
            "Enabled": false,
            "AllowedHosts": {
              "IpAddress": null,
              "IpNetwork": null,
              "AllIp": true
            }
          }]}}}]}
}
