
rule Detect_GIF89a_Less50KB
{
    meta:
        description = "Detect GIF89a images smaller than 50KB"

    strings:
        $header = { 47 49 46 38 39 61 }   // "GIF89a"

    condition:
        $header at 0 and filesize < 50KB
}


whoami@soc101-ubuntu:~$ yara -r Detect_GIF89a_Less50KB.yara ../../../YARA/Challenges/
Detect_GIF89a_Less50KB ../../../YARA/Challenges//Samples/Random/vJ8AWaf
whoami@soc101-ubuntu:~$
