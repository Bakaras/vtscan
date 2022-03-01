# vtscan
Virustotal integration for amavisd-new

vtscan is a script to include Virustotal as an amavisd-new virus scanner by using the Virustotal Public API.

## Installation
copy JSON.sh, vtscan.sh and vtscan-cache.sh to /usr/local/bin:


```
cp JSON.sh /usr/local/bin/. ; chmod +x /usr/local/bin/JSON.sh 
cp vtscan.sh /usr/local/bin/. ; chmod +x /usr/local/bin/vtscan.sh
cp vtscan-cache.sh /usr/local/bin/. ; chmod +x /usr/local/bin/vtscan-cache.sh
```

copy vtscan.cfg to /etc/vtscan:
```
mkdir /etc/vtscan
cp vtscan.cfg /etc/vtscan/.
```



To use with amavis add lines to /etc/amavis/conf.d/15-av_scanners:

```
['VirusTotal', 'vtscan.sh',
"{}",
[0], [99],
qr/(?:Virus found|Detected as) (.+)/m ],
```


