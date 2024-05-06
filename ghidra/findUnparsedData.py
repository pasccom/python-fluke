# Find unparsed bytes
#@author   Pascal COMBES
#@category Data
#@keybinding 
#@menupath 
#@toolbar 

# Print undefined code unit in current program fragment
for c in currentProgram.getListing().getDefaultRootModule().getChildren():
    if c.contains(currentAddress):
        currentFragment = c
	break
else:
    currentFragment = None
print(currentFragment)
if currentFragment is not None:
    beginAddr = None
    endAddr = None
    byteStr = ''
    for cu in currentFragment.getCodeUnits():
        if cu.getMnemonicString() == u'??':
            if beginAddr is None:
                beginAddr = cu.getMinAddress()
            endAddr = cu.getMaxAddress()
            byteStr = byteStr + ' ' + ' '.join(["{:02d}".format(b) for b in cu.getBytes()])
        elif beginAddr is not None:
            if (len(byteStr) > 48):
                byteStr = byteStr[0:25] + '...' + byteStr[-24:]	
            if endAddr.equals(beginAddr):			
                print("Undefined data at {}:{}".format(beginAddr, byteStr))
            else:
                print("Undefined data at {}-{}:{}".format(beginAddr, endAddr, byteStr))
            beginAddr = None
            endAddr = None
            byteStr = ''


