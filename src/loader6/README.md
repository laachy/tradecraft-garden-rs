link ../loader.spec ../../demo/bin/test.x64.dll out.bin %HOOKS="modules/xorhooks/xorhooks.spec"

link ../loader.spec ../../demo/bin/test.x64.dll out.bin %HOOKS="modules/stackcutting/stackcutting.spec"

link ../loader.spec ../../demo/bin/test.x64.dll out.bin %HOOKS="modules/xorhooks/xorhooks.spec,modules/stackcutting/stackcutting.spec"
