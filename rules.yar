rule General_Malware_Scan {
    meta:
        description = "General rule for detecting common malware characteristics"
        author = "Mahit Gupta"
        date = "2024-05-15"

    strings:
        // Common malware strings
        $str1 = "malware"
        $str2 = "virus"
        $str3 = "trojan"
        $str4 = "worm"
        $str5 = "backdoor"
        $str6 = "exploit"
        $str7 = "payload"
        $str8 = "keylogger"
        $str9 = "ransomware"
        
        // Common suspicious functions
        $fn1 = "CreateProcessA"
        $fn2 = "CreateProcessW"
        $fn3 = "VirtualAlloc"
        $fn4 = "VirtualProtect"
        $fn5 = "WriteProcessMemory"
        $fn6 = "ReadProcessMemory"
        $fn7 = "GetProcAddress"
        $fn8 = "LoadLibraryA"
        $fn9 = "LoadLibraryW"

        // Hex patterns commonly found in malware
        $hex1 = { 6A 40 68 00 30 00 00 6A 00 68 58 A4 53 E5 FF D5 }
        $hex2 = { E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 2E 8B 45 FC }

    condition:
        // Matches any of the defined strings, functions, or hex patterns
        5 of ($str*) or
        3 of ($fn*) or
        any of ($hex*)
}

rule NetworkAccessExecutable {
    meta:
        description = "Detects executables accessing network resources"
        author = "Mahit Gupta"
        date = "2024-05-15"

    strings:
        $socket = { 73 6F 63 6B 65 74 00 }          // "socket"
        $connect = { 63 6F 6E 6E 65 63 74 00 }      // "connect"
        $send = { 73 65 6E 64 00 }                  // "send"
        $recv = { 72 65 63 76 00 }                  // "recv"
        $inet_addr = { 69 6E 65 74 5F 61 64 64 72 00 } // "inet_addr"
        $gethostbyname = { 67 65 74 68 6F 73 74 62 79 6E 61 6D 65 00 } // "gethostbyname"
        $WSAStartup = { 57 53 41 53 74 61 72 74 75 70 00 } // "WSAStartup"
    condition:
        any of ($socket, $connect, $send, $recv, $inet_addr, $gethostbyname, $WSAStartup)
}

rule Detect_Custom_Signatures {
    meta:
        description = "Detects files containing the custom signature 'DEADBEEF' in both text and hex formats."
        author = "Mahit Gupta"
        date = "2024-05-15"

    strings:
        $sig_text = "DEADBEEF" ascii nocase // Detects "DEADBEEF" as a text string
        $sig_hex = {DE AD BE EF} // Detects the hexadecimal byte sequence

    condition:
        $sig_text or $sig_hex
}

rule HiddenSensitiveFiles {
    meta:
        description = "Detects hidden files in Linux containing sensitive information"
        author = "Mahit Gupta"
        date = "2024-05-15"

    strings:
        $password = "password"
        $secret = "secret"
        $confidential = "confidential"
        $privatee = "private"
    condition:
        any of ($password, $secret, $confidential, $privatee)
}

rule DetectMaliciousURLs {
    meta:
        description = "Detects if an executable file is trying to access malicious URLs or contains common malicious URL patterns"
        author = "Mahit Gupta"
        date = "2024-05-16"

    strings:
        // Specific known malicious URLs
        $url1 = "https://pancakesweetpancakemarseille.fr"
        $url2 = "http://www.quizambev.shop"
        $url3 = "http://6otaycm.duckdns.org/"

        // Generic malicious URL patterns
        $pattern1 = /\.xyz\b/
        $pattern2 = /\.top\b/
        $pattern3 = /\.club\b/
        $pattern4 = /\.info\b/
        $pattern5 = /\.online\b/
        $pattern6 = /\.site\b/
        $pattern7 = /malicious\b/
        $pattern8 = /phishing\b/
        $pattern9 = /hacked\b/
        $pattern10 = /evil\b/

        // Common malicious IP address patterns
        $ip_pattern1 = /\b192\.168\.\d{1,3}\.\d{1,3}\b/
        $ip_pattern2 = /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
        $ip_pattern3 = /\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b/

    condition:
        any of ($url*) or any of ($pattern*) or any of ($ip_pattern*)
}

rule DetectMaliciousScripts {
    meta:
        description = "Detects potentially malicious PowerShell, Python, Bash, and HTML scripts based on common suspicious patterns"
        author = "Mahit Gupta"
        date = "2024-05-16"

    strings:
        // PowerShell suspicious strings
        $ps1 = "#powershell" nocase
        $ps2 = "Invoke-WebRequest" nocase
        $ps3 = "Invoke-Expression" nocase
        $ps4 = "Start-Process" nocase
        $ps5 = "Import-Module" nocase
        $ps6 = "FromBase64String" nocase
        $ps7 = "New-Object Net.WebClient" nocase
        $ps8 = "Add-MpPreference" nocase

        // Python suspicious strings
        $py1 = /^#!.{0,100}python/ nocase
        $py2 = "import os" nocase
        $py3 = "import sys" nocase
        $py4 = "exec(" nocase
        $py5 = "eval(" nocase
        $py6 = "base64.b64decode" nocase
        $py7 = "subprocess.call" nocase
        $py8 = "socket" nocase

        // Bash suspicious strings
        $sh1 = /^#!.{0,100}\/bin\/bash/ nocase
        $sh2 = "curl " nocase
        $sh3 = "wget " nocase
        $sh4 = "base64 " nocase
        $sh5 = "nc " nocase
        $sh6 = "dd if=" nocase
        $sh7 = "chmod +x" nocase
        $sh8 = "eval " nocase

        // HTML/JavaScript suspicious strings
        $js1 = "<script>" nocase
        $js2 = "</script>" nocase
        $js3 = "eval(" nocase
        $js4 = "document.write(" nocase
        $js5 = "window.location" nocase
        $js6 = "fromCharCode" nocase
        $js7 = "XMLHttpRequest" nocase

    condition:
        // PowerShell conditions
        (any of ($ps1, $ps2, $ps3, $ps4, $ps5) and any of ($ps6, $ps7, $ps8)) or
        // Python conditions
        (any of ($py1, $py2, $py3) and any of ($py4, $py5, $py6, $py7, $py8)) or
        // Bash conditions
        (any of ($sh1, $sh2, $sh3) and any of ($sh4, $sh5, $sh6, $sh7, $sh8)) or
        // HTML/JavaScript conditions
        (any of ($js1, $js2) and any of ($js3, $js4, $js5, $js6, $js7))
}

rule WannaCry_Ransomware {
   meta:
      description = "Detects WannaCry Ransomware"
      author = "Florian Roth (with the help of binar.ly)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
   strings:
      $x1 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
      $x2 = "taskdl.exe" fullword ascii
      $x3 = "tasksche.exe" fullword ascii
      $x4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
      $x5 = "WNcry@2ol7" fullword ascii
      $x6 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
      $x7 = "mssecsvc.exe" fullword ascii
      $x8 = "C:\\%s\\qeriuwjhrf" fullword ascii
      $x9 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii

      $s1 = "C:\\%s\\%s" fullword ascii
      $s2 = "<!-- Windows 10 --> " fullword ascii
      $s3 = "cmd.exe /c \"%s\"" fullword ascii
      $s4 = "msg/m_portuguese.wnry" fullword ascii
      $s5 = "\\\\192.168.56.20\\IPC$" fullword wide
      $s6 = "\\\\172.16.99.5\\IPC$" fullword wide

      $op1 = { 10 ac 72 0d 3d ff ff 1f ac 77 06 b8 01 00 00 00 }
      $op2 = { 44 24 64 8a c6 44 24 65 0e c6 44 24 66 80 c6 44 }
      $op3 = { 18 df 6c 24 14 dc 64 24 2c dc 6c 24 5c dc 15 88 }
      $op4 = { 09 ff 76 30 50 ff 56 2c 59 59 47 3b 7e 0c 7c }
      $op5 = { c1 ea 1d c1 ee 1e 83 e2 01 83 e6 01 8d 14 56 }
      $op6 = { 8d 48 ff f7 d1 8d 44 10 ff 23 f1 23 c1 }
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and ( 1 of ($x*) and 1 of ($s*) or 3 of ($op*) )
}
