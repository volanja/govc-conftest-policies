package main

deny_incorrect_name[msg] {
	not input.Datacenters[0].Name == "ha-datacenter"
	msg := "Datacenter name is ha-datacenter"
}

deny_incorrect_overallstatus[msg] {
	not input.Datacenters[0].OverallStatus == "green"
	msg := "Datacenter OverallStatus should be set green"
}
