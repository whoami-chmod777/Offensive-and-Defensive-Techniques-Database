
import "pe"

rule EXE_Contains_youtubedownloadernew_com {
  meta:
    desc = "PEs containing the base domain youtubedownloadernew.com"
  strings:
    $dom = "youtubedownloadernew.com" ascii nocase
  condition:
    pe.is_pe and $dom
}


whoami@soc101-ubuntu:~$ yara -s domain_base.yar FreeYoutubeDownloader.exe.meow
EXE_Contains_youtubedownloadernew_com FreeYoutubeDownloader.exe.meow
0x358fa:$dom: youtubedownloadernew.com
0x35983:$dom: youtubedownloadernew.com
whoami@soc101-ubuntu:~$ 

whoami@soc101-ubuntu:~$ yara -s domain_base.yar FreeYoutubeDownloader.exe.meow | awk '/^0x/ {print $1}'
0x358fa:$dom:
0x35983:$dom:
whoami@soc101-ubuntu:~$ 
