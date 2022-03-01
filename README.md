# vtscan
Virustotal (virustotal.com) integration for amavis.

vtscan is a bash script to include Virustotal as an amavisd-new virus scanner by using the Virustotal Public API.

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

adjust settngs in vtscan.cfg:

create $QUARANTINEDIR and $CACHEDIR directories.

To use with amavis add lines to /etc/amavis/conf.d/15-av_scanners:

```
['VirusTotal', 'vtscan.sh',
"{}",
[0], [99],
qr/(?:Virus found|Detected as) (.+)/m ],
```

To make possible detection test with eicar.com
add the following to /etc/magic:
```
0	search/128	EICAR-STANDARD-ANTIVIRUS	Eicar test file
!:mime   application/x-eicar
```

