package main

test_correct_vmnic0_speed {
  msg := "vmnic0 is misconfigration. LinkSpped should be set 1000 Mbps."
  not deny_host_Pnic_vmnic_LinkSpeed[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Pnic": [
          {
            "Key": "key-vim.host.PhysicalNic-vmnic0",
            "Device": "vmnic0",
            "Pci": "0000:00:03.0",
            "Driver": "e1000",
            "LinkSpeed": {
              "SpeedMb": 1000,
              "Duplex": true
            },
            "Mac": "08:00:27:26:01:f9"
          }]}}}]
  }
}

test_incorrect_vmnic0_speed {
  msg := "vmnic0 is misconfigration. LinkSpped should be set 1000 Mbps."
  deny_host_Pnic_vmnic_LinkSpeed[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Pnic": [
          {
            "Key": "key-vim.host.PhysicalNic-vmnic0",
            "Device": "vmnic0",
            "Pci": "0000:00:03.0",
            "Driver": "e1000",
            "LinkSpeed": {
              "SpeedMb": 100,
              "Duplex": true
            },
            "Mac": "08:00:27:26:01:f9"
          }]}}}]
  }
}

test_correct_vmnic0_duplex {
  msg := "vmnic0 is misconfigration. Duplex should be set true."
  not deny_host_Pnic_vmnic_Duplex[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Pnic": [
          {
            "Key": "key-vim.host.PhysicalNic-vmnic0",
            "Device": "vmnic0",
            "Pci": "0000:00:03.0",
            "Driver": "e1000",
            "LinkSpeed": {
              "SpeedMb": 1000,
              "Duplex": true
            },
            "Mac": "08:00:27:26:01:f9"
          }]}}}]
  }
}

test_incorrect_vmnic0_duplex {
  msg := "vmnic0 is misconfigration. Duplex should be set true."
  deny_host_Pnic_vmnic_Duplex[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Pnic": [
          {
            "Key": "key-vim.host.PhysicalNic-vmnic0",
            "Device": "vmnic0",
            "Pci": "0000:00:03.0",
            "Driver": "e1000",
            "LinkSpeed": {
              "SpeedMb": 1000,
              "Duplex": false
            },
            "Mac": "08:00:27:26:01:f9"
          }]}}}]
  }
}

test_correct_vmnic0_driver {
  msg := "vmnic0 is misconfigration. Driver should be set e1000."
  not deny_host_Pnic_vmnic_Driver[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Pnic": [
          {
            "Key": "key-vim.host.PhysicalNic-vmnic0",
            "Device": "vmnic0",
            "Pci": "0000:00:03.0",
            "Driver": "e1000",
            "LinkSpeed": {
              "SpeedMb": 1000,
              "Duplex": true
            },
            "Mac": "08:00:27:26:01:f9"
          }]}}}]
  }
}

test_incorrect_vmnic0_driver {
  msg := "vmnic0 is misconfigration. Driver should be set e1000."
  deny_host_Pnic_vmnic_Driver[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Pnic": [
          {
            "Key": "key-vim.host.PhysicalNic-vmnic0",
            "Device": "vmnic0",
            "Pci": "0000:00:03.0",
            "Driver": "tg3",
            "LinkSpeed": {
              "SpeedMb": 1000,
              "Duplex": true
            },
            "Mac": "08:00:27:26:01:f9"
          }]}}}]
  }
}

test_correct_vmnic0_Mac {
  msg := "vmnic0 is misconfigration. MacAddress should be set 08:00:27:26:01:f9."
  not deny_host_Pnic_vmnic_Mac[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Pnic": [
          {
            "Key": "key-vim.host.PhysicalNic-vmnic0",
            "Device": "vmnic0",
            "Pci": "0000:00:03.0",
            "Driver": "e1000",
            "LinkSpeed": {
              "SpeedMb": 1000,
              "Duplex": true
            },
            "Mac": "08:00:27:26:01:f9"
          }]}}}]
  }
}

test_incorrect_vmnic0_Mac {
  msg := "vmnic0 is misconfigration. MacAddress should be set 08:00:27:26:01:f9."
  deny_host_Pnic_vmnic_Mac[msg] with input as {
  "HostSystems": [
    {
      "Config": {
        "Network": {
          "Pnic": [
          {
            "Key": "key-vim.host.PhysicalNic-vmnic0",
            "Device": "vmnic0",
            "Pci": "0000:00:03.0",
            "Driver": "e1000",
            "LinkSpeed": {
              "SpeedMb": 1000,
              "Duplex": true
            },
            "Mac": "11:22:33:44:55:66"
          }]}}}]
  }
}
