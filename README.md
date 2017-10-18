# Carbon Black - VirusTotal Connector

The VirusTotal connector submits binaries collected by Carbon Black to VirusTotal
for binary analysis. The results are collected and placed into an Intelligence
Feed on your Carbon Black server. The feed will then tag any binaries executed on your
endpoints identified as malware by VirusTotal. Only binaries submitted by the connector
for analysis will be included in the generated Intelligence Feed.

**To use this connector, you must have a VirusTotal Private API key. You cannot use a VirusTotal
Public API key as the Public API is severely rate limited.** You can
apply for a private API key through the VirusTotal web interface. VirusTotal Private API keys
are only available via a paid subscription to VirusTotal. For more information on the Private
API, see the [VirusTotal Frequently Asked Questions](https://www.virustotal.com/en/faq/#virustotal-api).

Log in to www.virustotal.com with your credentials, navigate to your profile -> settings and select the apikey tab.
There will be a button for requesting a private api key from VT. 
https://www.virustotal.com/#/settings/apikey

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-virustotal-connector
```

Once the software is installed via YUM, copy the `/etc/cb/integrations/virustotal/connector.conf.example` file to
`/etc/cb/integrations/virustotal/connector.conf`. Edit this file and place your Carbon Black API key into the
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

Then you must place your credentials for VirusTotal into the configuration file: place API token
into the `virustotal_api_token` variable in the
`/etc/cb/integrations/virustotal/connector.conf` file.

Any errors will be logged into `/var/log/cb/integrations/virustotal/virustotal.log`.

## Additional Configuration Options

### Full Binary Submission
By default, the Cb VirusTotal connector is configured to not send full binaries to VirusTotal for analysis, it will only send hashes. 

To enable FULL binary submission, change virustotal_deep_scan_threads to a value greater than 0. We recommend 1 or 2 threads.
You must also add the submit_full_binaries option and set it to 1.  These options need to be changed in the `connector.conf` file.

```
***WARNING SENDING FULL BINARIES TO VIRUSTOTAL IS A RISK ***
;
;submit_full_binaries=1
;virustotal_deep_scan_threads=1
;
```

### Virus Total Rescanning
By default, binaries which are already known by VirusTotal will not be resubmitted for rescanning.
If this functionality is desired, the rescan_window option can be added to the configuration file 
to set the window of time in which binaries are to be resubmitted for scanning.

```
;Window of time within which to rescan a submitted file
;rescan_window=1D
;FORMAT=%D%S
;S=H,M,D,W = hours,minutes,days,weeks
;NEVER= do not rescan binaries no matter how old the latest scan is (DEFAULT)
rescan_window=365D

```

## Troubleshooting

If you suspect a problem, please first look at the VirusTotal connector logs found here:
`/var/log/cb/integrations/virustotal/virustotal.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you want to re-run the analysis across your binaries:

1. Stop the service: `service cb-virustotal-connector stop`
2. Remove the database file: `rm /usr/share/cb/integrations/virustotal/db/sqlite.db`
3. Remove the feed from your Cb server's Threat Intelligence page
4. Restart the service: `service cb-virustotal-connector start`

## Contacting Carbon Black Developer Relations Support

Web: https://community.carbonblack.com/groups/developer-relations
E-mail: dev-support@bcarbonblack.com

### Reporting Problems

When you contact Carbon Black Developer Relations Technical Support with an issue, please provide the following:

* Your name, company name, telephone number, and e-mail address
* Product name/version, CB Server version, CB Sensor version
* Hardware configuration of the Carbon Black Server or computer (processor, memory, and RAM)
* For documentation issues, specify the version of the manual you are using.
* Action causing the problem, error message returned, and event log output (as appropriate)
* Problem severity

