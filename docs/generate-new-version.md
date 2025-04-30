# How to Generate a New Version

1. Inside dw-gdbserver:
   1. Bump version number in pyproject.toml
   2. git commit -a -m ...
   3. git push
   4. poetry install
   5. poetry build (for PyPi)
   6. poetry publish (also for PyPi)
   7. poetry run pyinstaller dw-gdbserver.spec
   8. rm -rf binaries/x86_64-apple-darwin/dw-*
   9. mv dist/dw-gdbserver/dw-gdbserver* binaries/x86_64-apple-darwin/
2. For each Linux-Arm, Windows, Linux-on-PC, macOS-Parallels
   1. run local newversion.sh
   1. This will populate the directories in fellas-fogg.github.io
3. Change into felas-fogg.github.io:
   1. Change into dw-tools
   2. Run ./packer.sh
   3. git add \<new tool packages\>
   4. git commit
   5. git push
4. Change into MiniCore
   1. Change version number before in Add_dw_tools
   2. Change dw-tools version number in Boads_manager
   3. create PR