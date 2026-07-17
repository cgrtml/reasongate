# ReasonGate stakes demo -> docs/stakes.gif
#
# Reproducible terminal recording (versioned like code). Generate with:
#   brew install vhs           # (pulls ttyd + ffmpeg)
#   pip install -e .           # reasongate on PATH
#   vhs docs/stakes.tape       # writes docs/stakes.gif
#
# Runs the deterministic mock backend (no API key), so the GIF is identical
# every time: Shield OFF breaches, Shield ON blocks, clean traffic passes, and a
# REWORDED attack slips past detection but is stopped by the action gate (run 4).

Output docs/stakes.gif

Set Shell "bash"
Set FontSize 12
Set Width 1100
Set Height 900
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 45ms

Type "python -m examples.stakes_demo.run"
Sleep 600ms
Enter
Sleep 9s
