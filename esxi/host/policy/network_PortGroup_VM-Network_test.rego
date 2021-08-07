package main

test_correct_VM_Network_vlan {
  msg := "VM Network is misconfigration. VLAN ID should be set 0."
  not deny_host_Portgroup_VM_Network_vlan[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Portgroup": [
            {
              "Spec": {
                "Name": "VM Network",
                "VlanId": 0
              }
            }]}}}]
  }
}

test_incorrect_VM_Network_vlan {
  msg := "VM Network is misconfigration. VLAN ID should be set 0."
  deny_host_Portgroup_VM_Network_vlan[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Portgroup": [
            {
              "Spec": {
                "Name": "VM Network",
                "VlanId": 1
              }
            }]}}}]
  }
}

test_correct_VM_Network_vSwtich {
  msg := "VM Network is misconfigration. vSwitch should be set vSwitch0."
  not deny_host_Portgroup_VM_Network_vSwitch[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Portgroup": [
            {
              "Spec": {
                "Name": "VM Network",
                "VswitchName": "vSwitch0"
              }
            }]}}}]
  }
}

test_incorrect_VM_Network_vSwtich {
  msg := "VM Network is misconfigration. vSwitch should be set vSwitch0."
  deny_host_Portgroup_VM_Network_vSwitch[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Portgroup": [
            {
              "Spec": {
                "Name": "VM Network",
                "VswitchName": "vSwitch1"
              }
            }]}}}]
  }
}
