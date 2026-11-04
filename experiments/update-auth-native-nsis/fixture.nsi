; Disposable self-contained FULL fixture. No Sable, registry, shortcuts or elevation.
Unicode true
RequestExecutionLevel user
SilentInstall silent
AutoCloseWindow true
SetCompressor zlib
Name "Disposable Native NSIS fixture"
OutFile "${OUTPUT}"
InstallDir "${TARGET}"
Section
  ; Compile-time target and handshakes belong exclusively to this RUNNER_TEMP run.
  StrCmp $INSTDIR "${TARGET}" +2
  Abort "Unexpected install directory"
  System::Call 'kernel32::GetCurrentProcessId() i .r0'
  FileOpen $1 "${READY}.writing" w
  FileWrite $1 '{"status":"READY","nonce":"${NONCE}","pid":$0}'
  FileClose $1
  Rename "${READY}.writing" "${READY}"
  System::Call 'kernel32::GetTickCount() i .r2'
  wait_ack:
    IfFileExists "${ACK}" ack_received
    System::Call 'kernel32::GetTickCount() i .r3'
    IntOp $3 $3 - $2
    IntCmp $3 120000 ack_timeout wait_more ack_timeout
  wait_more:
    Sleep 50 ; Poll an owned ACK with deadline, never an installation attestation.
    Goto wait_ack
  ack_timeout:
    SetErrorLevel 4
    Quit
  ack_received:
  ClearErrors ; Scope IfErrors to SetOutPath/File extraction, not earlier handshake commands.
  SetOutPath "$INSTDIR"
  File /r "${PAYLOAD}\*.*"
  IfErrors failed
  FileOpen $1 "${INSTALLED}.writing" w
  FileWrite $1 '{"status":"INSTALLED","nonce":"${NONCE}","pid":$0}'
  FileClose $1
  Rename "${INSTALLED}.writing" "${INSTALLED}"
  SetErrorLevel 0
  Goto done
  failed:
    FileOpen $1 "${INSTALLED}.writing" w
    FileWrite $1 '{"status":"EXTRACTION_FAILED","nonce":"${NONCE}","pid":$0}'
    FileClose $1
    Rename "${INSTALLED}.writing" "${INSTALLED}"
    SetErrorLevel 5
  done:
SectionEnd
