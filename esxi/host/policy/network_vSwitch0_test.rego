package main

test_correct_vSwitch0_MTU {
  msg := "vSwitch0 is misconfigration. MTU should be set 1500."
  not deny_host_vSwitch_MTU[msg]  with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Mtu": 1500,
            }]}}}]
  }
}

test_incorrect_vSwitch0_MTU {
  msg := "vSwitch0 is misconfigration. MTU should be set 1500."
  deny_host_vSwitch_MTU[msg]  with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Mtu": 9000,
            }]}}}]
  }
}

test_correct_vSwitch0_Portgroup {
  msg := "vSwitch0 is misconfigration. Portgroup should be set."
  not deny_host_vSwitch_Portgroup[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Portgroup": [
                "key-vim.host.PortGroup-VM Network",
                "key-vim.host.PortGroup-Management Network"
              ]
            }]}}}]
  }
}

test_incorrect_vSwitch0_PortgroupAll {
  msg := "vSwitch0 is misconfigration. Portgroup should be set."
  deny_host_vSwitch_Portgroup[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Portgroup": [
                "key-vim.host.PortGroup-Unset1",
                "key-vim.host.PortGroup-Unset2"
              ]
            }]}}}]
  }
}

test_incorrect_vSwitch0_Portgroup1 {
  msg := "vSwitch0 is misconfigration. Portgroup should be set."
  deny_host_vSwitch_Portgroup[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Portgroup": [
                "key-vim.host.PortGroup-Unset",
                "key-vim.host.PortGroup-Management Network"
              ]
            }]}}}]
  }
}

test_incorrect_vSwitch0_Portgroup2 {
  msg := "vSwitch0 is misconfigration. Portgroup should be set."
  deny_host_vSwitch_Portgroup[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Portgroup": [
                "key-vim.host.PortGroup-VM Network",
                "key-vim.host.PortGroup-Unset"
              ]
            }]}}}]
  }
}

test_correct_vSwitch0_PNIC {
  msg := "vSwitch0 is misconfigration. PNIC should be set vmnic0."
  not deny_host_vSwitch_PNIC[msg]  with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Pnic": [
                "key-vim.host.PhysicalNic-vmnic0"
              ],
            }]}}}]
  }
}

test_incorrect_vSwitch0_PNIC {
  msg := "vSwitch0 is misconfigration. PNIC should be set vmnic0."
  deny_host_vSwitch_PNIC[msg]  with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Pnic": [
                "key-vim.host.PhysicalNic-vmnic1"
              ],
            }]}}}]
  }
}

# All parameters is correct
test_correct_vSwitch0_Security {
  msg := "vSwitch0 is misconfigration. Security should be set."
  not deny_host_vSwitch_secutiry[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Spec": {
                "Policy": {
                  "Security": {
                    "AllowPromiscuous": false,
                    "MacChanges": true,
                    "ForgedTransmits": true
                  }
                }
              }
            }]}}}]
  }
}

# AllowPromiscuous is incorrect
test_incorrect_vSwitch0_Security_AllowP {
  msg := "vSwitch0 is misconfigration. Security should be set."
  deny_host_vSwitch_secutiry[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Spec": {
                "Policy": {
                  "Security": {
                    "AllowPromiscuous": true,
                    "MacChanges": true,
                    "ForgedTransmits": true
                  }
                }
              }
            }]}}}]
  }
}

# MacChanges is incorrect
test_incorrect_vSwitch0_Security_MacC {
  msg := "vSwitch0 is misconfigration. Security should be set."
  deny_host_vSwitch_secutiry[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Spec": {
                "Policy": {
                  "Security": {
                    "AllowPromiscuous": false,
                    "MacChanges": false,
                    "ForgedTransmits": true
                  }
                }
              }
            }]}}}]
  }
}

# ForgedTransmits is incorrect
test_incorrect_vSwitch0_Security_ForT {
  msg := "vSwitch0 is misconfigration. Security should be set."
  deny_host_vSwitch_secutiry[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Spec": {
                "Policy": {
                  "Security": {
                    "AllowPromiscuous": false,
                    "MacChanges": true,
                    "ForgedTransmits": false
                  }
                }
              }
            }]}}}]
  }
}


# All parameters is correct
test_correct_vSwitch0_NicTeaming {
  msg := "vSwitch0 is misconfigration. NicTeaming should be set."
  not deny_host_vSwitch_nicteaming[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Vswitch": [
            {
              "Name": "vSwitch0",
              "Spec": {
                "Policy": {
                  "NicTeaming": {
                    "Policy": "loadbalance_srcid",
                    "ReversePolicy": true,
                    "NotifySwitches": true,
                    "RollingOrder": false,
                    "NicOrder": {
                      "ActiveNic": [
                        "vmnic0"
                      ],
                      "StandbyNic": null
                    }
                  }
                }
              }
            }]}}}]
  }
}

