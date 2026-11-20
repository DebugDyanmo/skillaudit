Output demo.gif

Set Shell "powershell"
Set FontSize 18
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 60ms

Type "python -m skillaudit examples/safe-skill"
Enter
Sleep 3s

Type "clear"
Enter
Sleep 500ms

Type "python -m skillaudit examples/risky-skill --min-severity critical"
Enter
Sleep 8s
