# Building a Home-Scale Cloud SOC Environment for Threat Detection Using Microsoft Sentinel
Learn how I set up a cloud-based Security Operations Center (SOC) lab at home using Microsoft Azure and Sentinel.

I created a cloud-based SOC using Microsoft Azure and Sentinel. SOC stands for Security Operations Center, generally referred to the team responsible for monitoring, detecting and responding to cybersecurity threats. There are different tools that are used by the SOC like SIEM, EDR and SOAR.

The first step was to create a resource group - a container that holds related resources together. It can include virtual machines, virtual networks, etc. I named my resource group “RG-SOCLab” and chose a server close to my location.


The next step was to create a virtual network within this resource group. To do so, all I had to do was choose the correct resource group (i.e. RG_SOCLab) from the dropdown menu. I named the virtual network “VN-SOCLab” and selected the same region as my resource group.

Note: Throughout the process, in every step the azure subscription, resource group, and the region must be the same.
