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
2. For each Linux-Arm, Windows, Linux-on-PC:
   1. Move into Github/dw-gdbserver
   2. git pull
   3. poetry install
   4. poetry run pyinstaller dw-gdbserver.spec
   5. move new binary into the right folder binary/\<architecture\>
   6. commit + push
3. Change into felas-fogg.github.io:
   1. Change into dw-tools
   2. Run ./packer.sh
   3. git add \<new tool packages\>
   4. git commit
   5. git push
4. Change into MiniCore
   1. Add_dw_tools (change version number before)
   2. Add_Board_manager (change dw-tools version number and MiniCore version number)
   3. git commit/push