# VHS Recording Script for leak-sentinel
# Install VHS: brew install charmbracelet/vhs/vhs
# Run: vhs demo/demo.tape

Output demo/demo.gif

Set FontSize 14
Set Width 960
Set Height 580
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 50ms

Type "npx leak-sentinel"
Sleep 500ms
Enter

Sleep 3s

Type "# Launching local glassmorphism web dashboard..."
Sleep 500ms
Enter

Type "leak-sentinel --web"
Sleep 500ms
Enter

Sleep 4s
