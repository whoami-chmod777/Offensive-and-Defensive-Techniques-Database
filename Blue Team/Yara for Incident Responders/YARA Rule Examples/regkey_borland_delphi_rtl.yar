
rule Contains_Borland_Delphi_RTL_RegKey
{
    strings:
        $rk_ascii = "SOFTWARE\\Borland\\Delphi\\RTL" ascii nocase
        $rk_wide  = "SOFTWARE\\Borland\\Delphi\\RTL" wide nocase

    condition:
        any of them
}


whoami@soc101-ubuntu:~$ yara -r Contains_Borland_Delphi_RTL_RegKey.yar ../../../YARA/Challenges/
Contains_Borland_Delphi_RTL_RegKey ../../../YARA/Challenges//Samples/Random/c2RmZ2R
Contains_Borland_Delphi_RTL_RegKey ../../../YARA/Challenges//Samples/Random/ZmtsO2d
Contains_Borland_Delphi_RTL_RegKey ../../../YARA/Challenges//Samples/FreeYoutubeDownloader.exe.meow
whoami@soc101-ubuntu:~/Desktop/05_Threat_Intelligence/YARA/Challenges/Samples$


yara regkey_borland_delphi_rtl.yar -r /YARA/Challenges/ | awk '{print $2}' | xargs -n1 basename | sort -u
