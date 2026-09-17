# ReasonGate MCP gateway demo -> docs/mcp.gif
#
# Reproducible terminal recording. Generate with:
#   brew install vhs            # (pulls ttyd + ffmpeg)
#   pip install reasongate      # reasongate-mcp on PATH; npx for the filesystem server
#   vhs docs/mcp.tape           # writes docs/mcp.gif
#
# Runs examples/mcp_demo/host.py: the official filesystem MCP server behind the gateway,
# a poisoned file read normally, the write it dictates blocked, the wanted write through.

Output docs/mcp.gif

Set Shell "bash"
Set FontSize 13
Set Width 1180
Set Height 420
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 40ms

Hide
Type "export PATH=\$HOME/.local/bin:/usr/local/bin:$PATH; clear"
Enter
Sleep 500ms
Show

Type "python examples/mcp_demo/host.py"
Sleep 600ms
Enter
Sleep 15s
