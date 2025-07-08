# Building a Home-Scale Cloud SOC Environment for Threat Detection Using Microsoft Sentinel
Learn how I set up a cloud-based Security Operations Center (SOC) lab at home using Microsoft Azure and Sentinel.

## Description
I created a cloud-based SOC using Microsoft Azure and Sentinel. SOC stands for Security Operations Center, generally referred to the team responsible for monitoring, detecting and responding to cybersecurity threats. There are different tools that are used by the SOC like SIEM, EDR and SOAR.

The first step was to create a resource group - a container that holds related resources together. It can include virtual machines, virtual networks, etc. I named my resource group “RG-SOCLab” and chose a server close to my location.

<img src="https://github.com/shubodaya/HomeSOC/blob/8b56c75b438ac0f5a7c0f6e0199e02298212df50/Images/f1.png"/>

The next step was to create a virtual network within this resource group. To do so, all I had to do was choose the correct resource group (i.e. RG_SOCLab) from the dropdown menu. I named the virtual network “VN-SOCLab” and selected the same region as my resource group.

Note: Throughout the process, in every step the azure subscription, resource group, and the region must be the same.

<img src="https://github.com/shubodaya/HomeSOC/blob/8b56c75b438ac0f5a7c0f6e0199e02298212df50/Images/f2.png"/>

Next, I created a virtual machine on the VN-SOCLab virtual network. I gave it a name “TI-NET-SOUTH-1” just to make it look realistic as we need real hackers to attack the machine (the results were crazy!! 😉).

<img src="https://github.com/shubodaya/HomeSOC/blob/8b56c75b438ac0f5a7c0f6e0199e02298212df50/Images/f3.png"/>

Machine details:

Image: Windows 10 22H2
Size: Standard_B1s Or B2s (cheapest, free tier eligible)
In networks tab, check the “Delete public IP and NIC when VM is deleted”.
In monitoring, disable boot diagnostics.
Rest of the fields can be kept default/or any free tier eligible option. Do not forget the username and the password as it will be required to log in to the virtual machine later.

<img src="https://github.com/shubodaya/HomeSOC/blob/8b56c75b438ac0f5a7c0f6e0199e02298212df50/Images/f4.png"/>

After creating VM, the RG-SOCLab resource group should contain the following resources. Some of them are created automatically.

<img src="https://github.com/shubodaya/HomeSOC/blob/8b56c75b438ac0f5a7c0f6e0199e02298212df50/Images/f5.png"/>

One of the automatically created resources of specific importance is the Network Security Group (the name should end with “-nsg”). In the network security group, I deleted the default RDP inbound rule. Then I opened the settings menu on the left pane, and in the “Inbound security rules”, I created a new rule as given below:

```
Rule Name:                  DANGER_AllowAnyCustomAnyInbound
Priority:                   100
Action:                     Allow
Protocol:                   Any
Source:                     Any
Source Port Ranges:         *
Destination:                Any
Destination Port Ranges:    *
Service:                    Custom
```
Basically, this will open all ports on the virtual machine, offering free access to the attackers. A couple of warnings might be shown but it can be ignored as our aim is to make the machine vulnerable.

Now I connected to the virtual machine using the public IP address (can be found in the virtual machine dashboard; go to the resource group and click on the virtual machine). I logged into the machine from my Windows PC using RDP.

Once the machine is started, I turned off the firewall. To do that, open start menu and search “wf.msc”.

Open the Windows Defender Firewall properties dialog box an turn off all the tabs. Click Apply and then Ok.

<img src="https://github.com/shubodaya/HomeSOC/blob/8b56c75b438ac0f5a7c0f6e0199e02298212df50/Images/f7.png"/>

I closed the RDP connection and tried to connect with wrong usernames and passwords a few times. Then I logged in with the correct credentials. Opening the windows security logs in the Event Viewer, I checked if the failed login events are recorded. To do so, filter logs with event ID 4625 (which stands for failed login events). Opening the logs, you can find the incorrect usernames that tried to login. Half the work is done!

Now, I go to Sentinel, and I opened the Log Analytics Workspace. In the Content management dropdown menu, I select Content hub. Then I searched for “Windows Security Events” and installed it. After installation is complete, I clicked on the Manage button. Then I checked the “Windows Security Events via AMA” option and opened the connector page (refer to the image below).

<img src="https://github.com/shubodaya/HomeSOC/blob/8b56c75b438ac0f5a7c0f6e0199e02298212df50/Images/f8.png"/>

Now I created a new data collection rule and gave it a suitable name (eg. “DCR-Windows”). I selected the virtual machine in the resources tab and kept everything else default.

In the Logs tab inside the Log Analytics Workspace I chose the KQL (Kusto Query Language) mode and typed the command SecurityEvent and clicked Run.

You won’t get any results as it has just started to collect logs, but wait for 30-40 minutes and run this query again to see hundreds or thousands of log entries. These are real people trying to login to your virtual machine. The amount of attempts from all over the world in such a short time period is astounding.

<img src="https://github.com/shubodaya/HomeSOC/blob/8b56c75b438ac0f5a7c0f6e0199e02298212df50/Images/f9.png"/>

That’s almost it. Security events are getting logged, all that’s left is to connect the source IP addresses to its geographical location. And then it could be used to create a visual map.

Note: I made this SOC lab by following a YouTube video of Josh Madakor. Check the video and download the geolocation data spreadsheet from the description.
Link to video: https://www.youtube.com/watch?v=g5JL2RIbThM

I created a watchlist in Sentinel and uploaded the csv file. I put the name and alias of the watchlist as “geoip”. Wait for a few minutes for the spreadsheet data to get uploaded. There should be around 55k watchlist items.

Once uploading is complete, this query can be run using any attacker IP.
```
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == <attacker IP address>
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```
<img src="https://github.com/shubodaya/HomeSOC/blob/8b56c75b438ac0f5a7c0f6e0199e02298212df50/Images/f11.png"/>

As you can see in the image, it shows the geolocation data along with the other details together. Using this, I created a workbook to visually display all the locations from where the events are originating, and there frequency.

To do so, paste this JSON data in the “Advanced Editor” of the workbook query item, and save.

```
{
	"type": 3,
	"content": {
	"version": "KqlItem/1.0",
	"query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
	"size": 3,
	"timeContext": {
		"durationMs": 2592000000
	},
	"queryType": 0,
	"resourceType": "microsoft.operationalinsights/workspaces",
	"visualization": "map",
	"mapSettings": {
		"locInfo": "LatLong",
		"locInfoColumn": "countryname",
		"latitude": "latitude",
		"longitude": "longitude",
		"sizeSettings": "FailureCount",
		"sizeAggregation": "Sum",
		"opacity": 0.8,
		"labelSettings": "friendly_location",
		"legendMetric": "FailureCount",
		"legendAggregation": "Sum",
		"itemColorSettings": {
		"nodeColorField": "FailureCount",
		"colorAggregation": "Sum",
		"type": "heatmap",
		"heatmapPalette": "greenRed"
		}
	}
	},
	"name": "query - 0"
}
```

That’s it! The first image below is a screenshot taken after around half-an-hour. The second screenshot was taken after keeping the virtual machine on for 24 hours.

<img src="https://github.com/shubodaya/HomeSOC/blob/8b56c75b438ac0f5a7c0f6e0199e02298212df50/Images/f13.png"/>
<img src="https://github.com/shubodaya/HomeSOC/blob/8b56c75b438ac0f5a7c0f6e0199e02298212df50/Images/f14.png"/>
