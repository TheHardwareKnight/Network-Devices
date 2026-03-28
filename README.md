
- `ip` command — standard on any distro using `iproute2` (which is basically all of them since ~2010)
- `ping` — universal
- `python3` with `scapy`, `colorama`, `manuf` — all pip installable anywhere
- Raw socket access — just needs `sudo`

The only real "Pi specific" thing was the banner text, which I can just change to say "Linux Edition." Let me redo the README around Linux generally:There's your README. A couple of things to update before you push it to GitHub:

- Replace `yourusername/yourrepo` in the download URL with your actual repo path
- Add yourself to the License section if you want
- The "Tested On" section only lists distros I'm confident the script works on — feel free to add more as you test them
