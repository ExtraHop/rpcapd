; // ***** Sample.mc *****
; // This is the header section.

MessageIdTypedef=DWORD

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
Warning=0x2:STATUS_SEVERITY_WARNING
Error=0x3:STATUS_SEVERITY_ERROR
)

FacilityNames=(Application=0x0:FACILITY_APPLICATION)

LanguageNames=(English=0x409:win32-messages)

; // The following are message definitions.

MessageId=0x1
Severity=Success
Facility=Application
SymbolicName=MSG_SUCCESS
Language=English
Success: %1
.

MessageId=0x2
Severity=Informational
Facility=Application
SymbolicName=MSG_INFO
Language=English
Info: %1
.

MessageId=0x3
Severity=Warning
Facility=Application
SymbolicName=MSG_WARNING
Language=English
Warning: %1
.

MessageId=0x4
Severity=Error
Facility=Application
SymbolicName=MSG_ERROR
Language=English
Error: %1
.

