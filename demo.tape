Output demo.gif

Set Shell "powershell"
Set FontSize 15
Set Width 1200
Set Height 720
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type 'function prompt { "$ " }'
Enter
Type "clear"
Enter
Show

Type "# Found a cool agent skill online. Looks harmless..."
Enter
Sleep 1s
Type "Get-Content examples/risky-skill/SKILL.md"
Enter
Sleep 4s

Type "clear"
Enter
Type "# Let's audit it before installing"
Enter
Sleep 1s
Type "python -m skillaudit examples/risky-skill --min-severity high"
Enter
Sleep 10s
