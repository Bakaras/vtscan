# vtscan
Virustotal integration for amavisd-new

vtscan is a script to include Virustotal as an amavisd-new virus scanner by using the Virustotal Public API.

To use witch amavis add lines to /etc/amavis/conf.d/15-av_scanners:

```
['VirusTotal', 'vtscan.sh',
"{}",
[0], [99],
qr/(?:Virus found|Detected as) (.+)/m ],
```


