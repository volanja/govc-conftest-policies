package main

test_correct_InMaintenanceMode {
  msg := "Host is not InMaintenanceMode."
  json := {
    "HostSystems": [
      {
        "Name": "localhost.localdomain",
        "Runtime": {
          "InMaintenanceMode": false
        }
      }
    ]
  }

  not deny_InMaintenanceMode[msg] with input as json
}

test_incorrect_InMaintenanceMode {
  msg := "Host is not InMaintenanceMode."
  json := {
    "HostSystems": [
      {
        "Name": "localhost.localdomain",
        "Runtime": {
          "InMaintenanceMode": true
        }
      }
    ]
  }

  deny_InMaintenanceMode[msg] with input as json
}

