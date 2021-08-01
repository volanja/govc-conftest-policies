package main

test_correct_host_name {
  msg := "Host name should be set."
  json := {
    "HostSystems": [
      {
        "Name": "localhost.localdomain",
      }
    ]
  }

  not deny_host_name[msg] with input as json
}

test_incorrect_host_name {
  msg := "Host name should be set."
  json := {
    "HostSystems": [
      {
        "Name": "local.localdomain",
      }
    ]
  }

  deny_host_name[msg] with input as json
}

test_correct_domain_name {
  msg := "Host domain should be .localdomain"
  json := {
    "HostSystems": [
      {
        "Name": "localhost.localdomain",
      }
    ]
  }

  not deny_host_domain[msg] with input as json
}

test_incorrect_domain_name {
  msg := "Host domain should be .localdomain"
  json := {
    "HostSystems": [
      {
        "Name": "localhost.domain",
      }
    ]
  }

  deny_host_domain[msg] with input as json
}
