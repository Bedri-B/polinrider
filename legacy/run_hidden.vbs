' Launches the PolinRider server with NO visible window.
' Uses python.exe (not pythonw) so stdout handles exist; output goes to server.log.
Dim sh, dir
Set sh = CreateObject("WScript.Shell")
dir = "C:\Users\hp\polinrider-tools"
sh.CurrentDirectory = dir
sh.Environment("PROCESS")("PYTHONUTF8") = "1"
' window style 0 = hidden, False = do not wait
sh.Run "cmd /c """"" & dir & "\.venv\Scripts\python.exe"" polinrider_app.py --port 7860 >> """ & dir & "\server.log"" 2>&1""", 0, False
