
import "pe"

rule EXE_Contains_tmp1E2A_JPG {
  strings:
    $a = "tmp1E2A.jpg" ascii nocase
    $w = "tmp1E2A.jpg" wide  nocase
  condition:
    any of them
}


whoami@soc101-ubuntu:~$ yara -s EXE_Contains_tmp1E2A_JPG.yar HawkEye.exe.meow 
Contains_tmp1E2A_JPG HawkEye.exe.meow
0x1115d:$a: tmp1E2A.jpg
