
rule Detect_GIF89a_Over50KB
{
    meta:
        description = "Detect GIF89a images larger than 50KB"

    strings:
        $header = { 47 49 46 38 39 61 }   // "GIF89a"

    condition:
        $header at 0 and filesize > 50KB
}


whoami@soc101-ubuntu:~$ yara -r Detect_GIF89a_Over50KB.yar ../../../YARA/Challenges/
Detect_GIF89a_Over50KB ../../../YARA/Challenges//Samples/Random/fEbZizl
whoami@soc101-ubuntu:~$ 
