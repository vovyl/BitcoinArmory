from armoryengine.ArmoryUtils import *
from armoryengine.BinaryUnpacker import *
from armoryengine.BinaryPacker import *
from armoryengine.PyBtcAddress import *
from armoryengine.PyBtcWallet import *
from qtdialogs import *

class PyBtcWalletRecovery(object):
   """
   Fail safe wallet recovery tool. Reads a wallet, verifies and extracts sensitive data to a new file.

   """

#############################################################################
   def BuildLogFile(self, WalletPath, errorCode=0):
      """
      The recovery function has ended and called this. Review the analyzed data, build a log and return negative values if the recovery couldn't complete
      
      """

      newWalletPath = WalletPath + ".log"
      basename = os.path.basename(WalletPath)
            
      self.logfile = open(newWalletPath, 'ab')
      self.logfile.write('Recovering wallet %s on %s: \r\n' % (basename, time.ctime()))
      self.logfile.write('Using %s recovery mode\r\n' % (self.smode))
      
      if errorCode == -1:
         self.logfile.write('ERROR: no such file at given path\r\n')
         self.EndLog()
         return errorCode
      elif errorCode == -2:
         self.logfile.write('ERROR: failed to pass consistency check\r\n')
         self.EndLog()
         return errorCode
      elif errorCode == -3:
         self.logfile.write('ERROR: failed to unpack wallet header\r\n')
         self.EndLog()
         return errorCode
      elif errorCode == -4:
         self.logfile.write('ERROR: invalid or missing passphrase for encrypted wallet\r\n')
         self.EndLog()
         return errorCode      
           
      if self.WO == 0:
         self.logfile.write('Wallet is Watch Only\r\n')
      else:
         self.logfile.write('Wallet contains private keys ')
         if self.useEnc == 0:
            self.logfile.write('and doesn\'t use encryption\r\n')
         else:
            self.logfile.write('and uses encryption')
            
      self.logfile.write('The wallet file is %d  bytes, of which %d bytes were readable\r\n' % (self.fileSize, self.dataLastOffset))
      self.logfile.write('%d chain addresses, %d imported keys and %d comments were found\r\n')
            
      #### chained keys      
      self.logfile.write('Found %d chained address entries\r\n' % (self.naddress))
      
      if len(self.brokenSequence) == 0:
         self.logfile.write('All chained addresses were arranged sequentially in the wallet file\r\n')
      else:
         self.logfile.write('The following %d addresses were not arranged sequentially in the wallet file:\r\n' % (len(self.brokenSequence)))
         for i in range(0, len(self.brokenSequence)):
            self.logfile.write('   chainIndex %s at file offset %s\r\n' % (self.brokenSequence[i][0], self.brokenSequence[i][1]))
            
      if len(self.sequenceGaps) == 0:
         self.logfile.write('There are no gaps in the address chain\r\n')
      else:
         self.logfile.write('Found %d gaps in the address chain:\r\n' % (len(self.sequenceGaps)))
         for i in range(0, len(self.sequenceGaps)):
            self.logfile.write('   from chainIndex %d to %d\r\n' % (self.sequenceGaps[i][0], self.sequenceGaps[i][1]))
      
      if len(self.brokenPublicKeyChain) == 0:      
         self.logfile.write('No invalid chained public address was found\r\n')
      else:
         self.logfile.write('Found %d invalid chained public addresses:\r\n' % (len(self.brokenPublicKeyChain)))
         for i in range(0, len(self.brokenPublicKeyChain)):
            self.logfile.write('   at chainIndex %d, file offset %s\r\n' % (self.brokenPublicKeyChain[i][0], self.brokenPublicKeyChain[i][1]))
            
      if len(self.chainCodeCorruption) == 0:
         self.logfile.write('No chaincode corruption was found\r\n')
      else:
         self.logfile.write('Found %d instances of chaincode corruption:\r\n' % (len(self.chainCodeCorruption)))
         for i in range(0, len(self.chainCodeCorruption)):
            self.logfile.write('   at chainIndex %d, file offset %d\r\n' % (self.chainCodeCorruption[i][0], self.chainCodeCorruption[i][1]))
            
      if len(self.invalidPublicKey) == 0:
         self.logfile.write('All chained public keys are valid EC points\r\n')
      else:
         self.logfile.write('%d chained public keys are invalid EC points:\r\n' % (len(self.invalidPublicKey)))
         for i in range(0, len(self.invalidPublicKey)):
            self.logfile.write('   at chainIndex %d, file offset %d' % (self.invalidPublicKey[i][0], self.invalidPublicKey[i][1]))
            
      if len(self.missingPubKey) == 0:
         self.logfile.write('No chained public key is missing\r\n')
      else:
         self.logfile.write('%d chained public keys are missing:\r\n' % (len(self.missingPubKey)))
         for i in range(0, len(self.missingPubKey)):
            self.logfile.write('   at chainIndex %d, file offset %d' % (self.missingPubKey[i][0], self.missingPubKey[i][1]))

      if len(self.hashValMismatch) == 0:
         self.logfile.write('All entries were saved under their matching hashVal\r\n')
      else:
         self.logfile.write('%d address entries were saved under an erroneous hashVal:\r\n' % (len(self.hashValMismatch)))
         for i in range(0, len(self.hashValMismatch)):
            self.logfile.write('   at chainIndex %d, file offset %d\r\n' % (self.hashValMismatch[i][0], self.hashValMismatch[i][1]))
      
      if self.WO == 1:  
         if len(self.unmatchedPair) == 0:
            self.logfile.write('All chained public keys match their respective private keys\r\n')
         else:
            self.logfile.write('%d public keys do not match their respective private key:\r\n' % (len(self.unmatchedPair)))
            for i in range(0, len(self.unmatchedPair)):
               self.logfile.write('   at chainIndex %d, file offset %d\r\n' % (self.unmatchedPair[i][0], self.unmatchedPair[i][1]))
            
      if len(self.misc) > 0:
         self.logfile.write('%s miscalleneous errors were found:\r\n')
         for i in range(0, len(self.misc)):
            self.logfile.write('   %d' % self.misc[i])
      
      #### imported keys      
      self.logfile.write('Found %d imported address entries\r\n' % (self.nImports))
      
      if len(self.importedErr) == 0:
         self.logfile.write('No errors were found within the imported address entries\r\n')
      else:
         self.logfile.write('%d errors were found within the imported address entries:\r\n' % (len(self.importedErr)))
         for i in range(0, len(self.importedErr)):
            self.logfile.write('   %s' % (self.importedErr[i]))
      
      #### comments
            
      self.EndLog()
      return 0 
   
   def EndLog(self):
      
      self.logfile.write('Recovery done\r\n\r\n\r\n')
      self.logfile.close()
   
   #############################################################################
   def RecoverWallet(self, WalletPath, Passphrase=None, Mode='Bare', GUI=False):
      """
      Modes:
         1) Stripped: Only recover the root key and chaincode (it all sits in the header). As fail safe as it gets.

         2) Bare: Recover root key, chaincode and valid private/public key pairs. Verify integrity of the wallet and consistency of all entries encountered.
            Skips comments, unprocessed public keys and otherwise corrupted data without attempting to fix it.

         3) Full: Recovers as much data as possible from the wallet.
         
         4) Meta: Get all labels and comment entries from the wallet, return as list
      """

      rmode = 2
      self.smode = 'bare'
      if Mode == 'Stripped' or Mode == 1: 
         rmode = 1
         self.smode = 'stripped'
      elif Mode == 'Full' or Mode == 3: 
         rmode = 3
         self.smode = 'full'
      elif Mode == 'Meta' or Mode == 4: 
         rmode = 4
         self.smode = 'meta'

      self.fileSize=0
      if not os.path.exists(WalletPath):
         if GUI:
            self.BadPath(WalletPath)
            return
         else:
            return self.BuildLogFile(WalletPath, -1)
      else: 
         self.fileSize = os.path.getsize(WalletPath)

      toRecover = PyBtcWallet()
      toRecover.walletPath = WalletPath

      #consistency check
      try:
         toRecover.doWalletFileConsistencyCheck()
      except KeyDataError, errmsg:
         return self.BuildLogFile(WalletPath, -2)

   #TODO: stronger checks on the path fed

      #fetch wallet content
      wltfile = open(WalletPath, 'rb')
      wltdata = BinaryUnpacker(wltfile.read())
      wltfile.close()

      #unpack header
      returned = toRecover.unpackHeader(wltdata)
      if returned < 0:
         return self.BuildLogFile(WalletPath, -3)
      
      self.useEnc=0

      #check for private keys (watch only?)
      if toRecover.watchingOnly is True:
         LOGWARN('no private keys in this wallet, checking for chain consistency')
         self.WO = 1
      else:
         #check if wallet is encrypted
         self.WO = 0
         if toRecover.isLocked==True and Passphrase==None and rmode < 4:
            #locked wallet and no passphrase, prompt the user if we're using the gui           
            if GUI==True:
               self.AskUnlock()
            else:
               LOGWARN('Locked wallet, no passphrase!')
               return self.BiuldLogFile(WalletPath, -4)
            
         newAddr = toRecover.addrMap['ROOT']

         #if the wallet uses encryption, unlock ROOT and verify it
         if toRecover.isLocked:
            self.useEnc
            LOGWARN('deriving passphrase')
            SecurePassphrase = SecureBinaryData(Passphrase)
            if not toRecover.kdf:
               raise EncryptionError, 'How do we have a locked wallet w/o KDF???'
            secureKdfOutput = toRecover.kdf.DeriveKey(SecurePassphrase)

            LOGWARN('checking passphrase against wallet')
            if not toRecover.verifyEncryptionKey(secureKdfOutput):
               raise PassphraseError, "Incorrect passphrase for wallet"
            toRecover.kdfKey = secureKdfOutput

            LOGWARN('attempting to unlock root key')
            try:
               newAddr.unlock(toRecover.kdfKey)
            except:
               LOGERROR('failed to unlock root key')
               return -2

            LOGWARN('root key unlocked successfully')
         else:
            SecurePassphrase = None
            LOGWARN('wallet is not encrypted')

         #create recovered wallet
         if rmode != 4:
            RecoveredWallet = PyBtcWallet()
            newwalletPath = os.path.join(os.path.dirname(toRecover.walletPath), 'armory_%s_RECOVERED.wallet' % (toRecover.uniqueIDB58))
            if os.path.exists(newwalletPath):
               LOGERROR('recovery file already exist!')
               return -3
   
            LOGWARN('creating recovery from root key')
            RecoveredWallet.createNewWallet(newWalletFilePath=newwalletPath, securePassphrase=SecurePassphrase, \
                                            plainRootKey=newAddr.binPrivKey32_Plain, chaincode=newAddr.chaincode, \
                                            #not registering with the BDM, so no addresses are computed
                                            doRegisterWithBDM=False, \
                                            shortLabel=toRecover.labelName, longLabel=toRecover.labelDescr)
            LOGWARN('recovery file created successfully')
   
            if rmode == 1: self.RecoveryDone() #stripped recovery, we are done

      
      
      
      #address entries may not be saved sequentially. To check the address chain is valid, all addresses will be unserialized
      #and saved by chainIndex in addrDict. Then all addresses will be checked for consistency and proper chaining. Imported 
      #private keys and comments will be added at the tail of the file.
      
      self.naddress = 0
      addrDict = {} #holds address chain sequentially, ordered by chainIndex
      
      self.nImports = 0
      importedDict = {} #holds imported address, by order of apparition
      
      self.ncomments = 0
      commentDict = {} #holds all comments entries
            
      #move on to wallet body
      toRecover.lastComputedChainIndex = -UINT32_MAX
      toRecover.lastComputedChainAddr160  = None
      LOGWARN('Now parsing')
      while wltdata.getRemainingSize()>0:
         byteLocation = wltdata.getPosition()

         try:
            dtype, hashVal, rawData = toRecover.unpackNextEntry(wltdata)
         except:
            #error in the binary file content. Try to open the next entry by forwarding by possible entry sizes
            LOGERROR('Unpack error')
            break

         if dtype==WLT_DATATYPE_KEYDATA and rmode != 4:
            newAddr = PyBtcAddress()
            newAddr.unserialize(rawData)
            newAddr.walletByteLoc = byteLocation + 21

            if newAddr.useEncryption:
               newAddr.isLocked = True
             
            #save address entry count in the file, to check for entry sequence
            if newAddr.chainIndex > -2 :
               addrDict[newAddr.chainIndex] = [newAddr, hashVal, self.naddress, byteLocation]
               self.naddress = self.naddress +1
            else:
               importedDict[self.nImports] = [newAddr, hashVal, byteLocation]
               self.nImports = self.nImports +1
               

         elif dtype in (WLT_DATATYPE_ADDRCOMMENT, WLT_DATATYPE_TXCOMMENT):
            if rmode == 3: 
               commentDict[self.ncomments] = [rawData, hashVal, dtype]
               self.ncomments = self.ncomments +1

         elif dtype==WLT_DATATYPE_OPEVAL:
            LOGWARN('OP_EVAL not supported in wallet yet')
            pass
         elif dtype==WLT_DATATYPE_DELETED:
            pass
         else:
            LOGERROR('invalid dtype: %d' % (dtype))
            #try same trick as to recover from unpack errors
            
      self.dataLastOffset = wltdata.getPosition()

      #TODO: verify chainIndex 0 was derived from the root key

      currSequence = addrDict[0].chainIndex
      """
      Set of lists holding various errors at given indexes. Used at the end of the recovery process to compile a wallet specific log of encountered
      inconsistencies
      """
      self.brokenSequence = [] #inconsistent address entry order in the file
      self.sequenceGaps = [] #gaps in key pair chain
      self.brokenPublicKeyChain = [] #for public keys: (N-1)*chaincode != N
      self.chainCodeCorruption = [] #addr[N] chaincode doesnt match addr[0] chaincode
      self.invalidPubKey = [] #pub key isnt a valid EC point
      self.missingPubKey = [] #addr[N] has no pub key
      self.hashValMismatch = [] #addrStr20 doesnt match hashVal entry in file      
      self.unmatchedPair = [] #private key doesnt yield public key
      self.misc = [] #miscellaneous errors
      self.importedErr = [] #all imported keys related errors
      
      chaincode = addrDict[0][0].chainCode.toHexStr()
      
      #chained key pairs. for rmode is 4, no need to skip this part, naddress will be 0
      for i in range(0, self.naddress):      
         entrylist = []
         entrylist = list(addrDict[i])
         newAddr = entrylist[0]
         
         # Fix byte errors in the address data         
         fixedAddrData = newAddr.serialize()
         if not rawData==fixedAddrData:
            LOGWARN('found byte error in address data')
            newAddr = PyBtcAddress()
            newAddr.unserialize(fixedAddrData)
            entrylist[0] = newAddr
            addrDict[i] = entrylist
        
         #check public key is a valid EC point
         if newAddr.hasPubKey():
            CryptoECDSA().VerifyPublicKeyValid(newAddr.binPubKey65)
            LOGERROR('invalid pub key at chainIndex %d in wallet %s' % (newAddr.chainIndex, WalletPath))
            self.invalidPubKey.append([newAddr.chainIndex, byteLocation])
         else:
            LOGWARN('missing pub key at chainIndex %d in wallet %s' % (newAddr.chainIndex, WalletPath))
            self.missingPubKey.append([newAddr.chainIndex, byteLocation])
         
         #check chaincode consistency
         newCC = newAddr.chainCode.toHexStr()
         if newCC != chaincode:
            LOGWARN('chaincode curroption at index: %d in wallet %s' % (newAddr.chainIndex, WalletPath))
            self.chainCodeCorruption.append([newAddr.chainIndex, byteLocation])
            
         #check the address entry sequence
         nextSequence = newAddr.chainIndex
         if nextSequence != currSequence:
            if (nextSequence - currSequence) != 1:
               self.brokenSequence.append([newAddr.chainIndex, entrylist[3]])
         currSequence = nextSequence
         
         #check for gaps in the sequence
         if newAddr.chainIndex >0:
            seq = newAddr.chainIndex -1
            prevEntry = []
            while seq > 0:
               try:
                  prevEntry = addrDict[seq]
                  break
               except:
                  continue
               seq = seq -1
               
            prevEntry = list(addrDict[seq])
            
            gap = newAddr.chainIndex - seq
            if gap > 1:
               self.sequenceGaps.append([seq, newAddr.chainIndex])
         
            #check public address chain
            if newAddr.hasPubKey():
               prevAddr = prevEntry[0]
               
               cid = 0
               extended = prevAddr.binPubKey65
               while cid < gap:
                  extended = CryptoECDSA().ComputeChainedPublicKey(extended, prevAddr.chaincode)
                  cid = cid +1
                  
               if extended.toHexStr() != newAddr.binPubKey.tohexStr():
                  LOGERROR('Broken public key chain at index %d in wallet %s' % (newAddr.chainIndex, WalletPath))
                  self.brokenPublicKeyChain.append([newAddr.chainIndex, byteLocation])
            

         if not toRecover.watchingOnly:            
            #not a watch only wallet, check private key chaining and integrity   
           
            #check private key against public key, possibly compute missing ones, depending on the recovery mode
            
            #TODO: if the public key is forked but it's private key matches, save as imported key pair
            #      if a private key forked, save as imported pair
            
            keymismatch=0
            """
            0: public key matches private key
            1: public key doesn't match private key
            2: private key is missing (encrypted)
            3: public key is missing
            4: private key is missing (unencrypted)
            """
            if not newAddr.hasPrivKey():
               #if the entry has no private key, mark it for computation
               keymismatch=2

               if newAddr.chainIndex >= 0:
                  #chained private key
                  if newAddr.createPrivKeyNextUnlock:
                     #have to build the private key on unlock; we can use prevAddr for that purpose, used to chain the public key off of
                     if newAddr.createPrivKeyNextUnlock:
                        newAddr.createPrivKeyNextUnlock_IVandKey[0] = prevAddr.binInitVect16.copy()
                        newAddr.createPrivKeyNextUnlock_IVandKey[1] = prevAddr.binPrivKey32_Encr.copy()

                        newAddr.createPrivKeyNextUnlock_ChainDepth = newAddr.chainIndex - newAddr.chainIndex
                  else:
                     if not newAddr.useEncryption:
                        #uncomputed private key in a non encrypted wallet? definitely not supposed to happen
                        keymismatch = 4
                        LOGERROR('uncomputed private key in unencrypted wallet at chainIndex %d in wallet %s' % (newAddr.chainIndex, WalletPath))
                        self.misc.append('uncomputed private key in unencrypted wallet at chainIndex %d in wallet %s' % (newAddr.chainIndex, WalletPath))
                  
            #unlock if necessary      
            if keymismatch == 0 or keymismatch == 2:               
               if newAddr.isLocked:     
                  try:
                     newAddr.unlock(toRecover.kdfKey)
                     keymismatch = 0
                  except KeyDataError: 
                     keymismatch=1

            #deal with mismatch scenarios   
            if keymismatch == 1:
               newAddr.binPublicKey65 = CryptoECDSA().ComputePublicKey(self.binPrivKey32_Plain)
               LOGERROR('pub key doesnt match private key at chainIndex %d in wallet %s' % (newAddr.chainIndex, WalletPath))
               self.unmatchedPair.append(newAddr.chainIndex)
               keymismatch = 0
               
            elif keymismatch == 2:
               LOGERROR('no private at chainIndex %d in wallet %s' % (newAddr.chainIndex, WalletPath))
               
            elif keymismatch == 3:
               newAddr.binPublicKey65 = CryptoECDSA().ComputePublicKey(self.binPrivKey32_Plain)
               newAddr.addrStr20 = newAddr.binPublicKey65.getHash160()                  
               keymismatch = 0

            #if we have clear possible mismatches (or there were none), proceed to consistency checks
            if keymismatch == 0:
               if not CryptoECDSA().CheckPubPrivKeyMatch(newAddr.binPrivKey32_Plain, newAddr.binPubKey65):
                  LOGERROR('pub key doesnt match private key at chainIndex %d in wallet %s' % (newAddr.chainIndex, WalletPath))
                  self.unmatchedPair.append([newAddr.chainIndex, byteLocation])
                 
               if newAddr.addrStr20 != entrylist[1]:
                  LOGERROR('addr hash160 doesnt match the hashVal it was saved under at chainIndex %d in wallet %s' % (newAddr.chainIndex, WalletPath))
                  self.hashValMismatch.append([newAddr.chainIndex, byteLocation])
   
            if newAddr.useEncryption:
               newAddr.lock(toRecover.kdfKey)
   

      #imported addresses
      for i in range(0, self.nImports):
         entrylist = []
         entrylist = list(importedDict[i])
         newAddr = entrylist[0]
         
         # Fix byte errors in the address data         
         fixedAddrData = newAddr.serialize()
         if not rawData==fixedAddrData:
            LOGWARN('found byte error in address data')
            newAddr = PyBtcAddress()
            newAddr.unserialize(fixedAddrData)
            entrylist[0] = newAddr
            importedDict[i] = entrylist
        
         #check public key is a valid EC point
         if newAddr.hasPubKey():
            CryptoECDSA().VerifyPublicKeyValid(newAddr.binPubKey65)
            LOGERROR('invalid pub key for imported address %d in wallet %s' % (i, WalletPath))
            self.importedErr.append('invalid pub key for imported address %d at file offset %d' % (i, entrylist[2]))
         else:
            LOGWARN('missing pub key for imported address %d in wallet %s' % (i, WalletPath))
            self.importedErr.append('missing pub key for imported address %d at file offset %d' % (i, entrylist[2]))
         
         #if there a private key in the entry, check for consistency   
         if not newAddr.hasPrivKey():
            LOGWARN('missing private key for imported address %d in wallet %s' % (i, WalletPath))
            self.importedErr.append('missing private key for imported address %d at file offset %d' % (i, entrylist[2]))
         else:
            keymismatch = 0
            if newAddr.isLocked:
               try:
                  newAddr.unlock(toRecover.kdfKey)
               except KeyDataError:
                  keymismatch = 1
                  LOGWARN('pub key doesnt match private key for imported address %d in wallet %s' % (i, WalletPath))
                  self.importedErr.append('pub key doesnt match private key for imported address %d at file offset %d' % (i, entrylist[2]))
            
                  
            if keymismatch == 0:
               #pubkey is present, check against priv key
               if not CryptoECDSA().CheckPubPrivKeyMatch(newAddr.binPrivKey32_Plain, newAddr.binPubKey65):
                  keymismatch = 1
                  LOGWARN('pub key doesnt match private key for imported address %d in wallet %s' % (i, WalletPath))
                  self.importedErr.append('pub key doesnt match private key for imported address %d at file offset %d' % (i, entrylist[2]))
            
            if keymismatch == 1:
               #compute missing/invalid pubkey                    
               newAddr.binPublicKey65 = CryptoECDSA().ComputePublicKey(newAddr.binPrivKey32_Plain)
 
            #check hashVal   
            if newAddr.addrStr20 != entrylist[1]:
               newAddr.addrStr20 = newAddr.binPublicKey65.getHash160()
               LOGWARN('hashVal doesnt match addrStr20 for imported address %d in wallet %s' % (i, WalletPath))
               self.importedErr.append('hashVal doesnt match addrStr20 for imported address %d at file offset %d' % (i, entrylist[2]))
               
            #if the entry was encrypted, lock it back with the new wallet kdfkey
            if newAddr.useEncryption:
               newAddr.lock(RecoveredWallet.kdfKey)
               
      #TODO: check comments consistency
      
      if rmode < 4:
         #build address pool
         RecoveredWallet.fillAddressPool(self.naddress, True, False)
      
         #save imported addresses
         for i in range(0, self.nImports):
            entrylist = []
            entrylist = list(importedDict[i])
            newAddr = entrylist[0]            
            RecoveredWallet.walletFileSafeUpdate([[WLT_UPDATE_ADD, WLT_DATATYPE_KEYDATA, newAddr.addrStr20, newAddr]])
      
         #save comments
         if rmode == 3:
            for i in range(0, self.ncomments):
               entrylist = []
               entrylist = list(importedDict[i])    
               RecoveredWallet.walletFileSafeUpdate([[WLT_UPDATE_ADD, entrylist[2], entrylist[1], entrylist[0]]]) 
      
      
      #nothing to process anymore at this point. if the recovery mode is 4 (meta), just return the comments dict
      #now to build the specific log file
      
      #TODO: clean up kdf params in both wallets
                        
      return self.BuildLogFile(WalletPath)

   #############################################################################
   #GUI related members start here
   #############################################################################
   #############################################################################
   def UIRecoverWallet(self):
      """
      Prompts the user with a window asking for wallet path and recovery mode.
      Proceeds to Recover the wallet. Prompt for password if the wallet is locked
      """

      dlg = DlgHelpRecoverWallet()
      if dlg.exec_():
         path = str(dlg.edtWalletPath.text())
         LOGWARN(path)
      else:
         return False
   
   #############################################################################   
   def BadPath(self, WalletPath):
      dlg = DlgBadPath(WalletPath)

      if dlg.exec_():
         return
      else: return

   ##############
   def AskUnlock(self, wll):
      dlg = DlgUnlockWallet(wll)

      if dlg.exec_():
         #at this point wallet should have the proper derivated key in kdf
         return
      else: return
      
################################################################################
class DlgHelpRecoverWallet(ArmoryDialog):
   def __init__(self, parent=None, main=None):
      super(DlgHelpRecoverWallet, self).__init__(parent)

      self.edtWalletPath = QLineEdit()
      self.btnWalletPath = createDirectorySelectButton(self, self.edtWalletPath)

      lblDesc = QRichLabel('<b>Wallet Recovery Tool:</b><br>'
                           'This tools attempts to recover data from damaged wallets.<br>'
                           'Point to your wallet path and pick a recovery mode according to it\'s damage level'
                           )
      lblDesc.setScaledContents(True)

      lblWalletPath = QRichLabel('Wallet Path:')


      layoutMgmt = QGridLayout()
      layoutMgmt.addWidget(lblDesc, 0, 0, 1, 3)
      layoutMgmt.addWidget(lblWalletPath, 1, 0)
      layoutMgmt.addWidget(self.edtWalletPath, 1, 1)
      layoutMgmt.addWidget(self.btnWalletPath, 1, 2)

      self.rdbtnStripped = QRadioButton()
      self.rdbtnStripped.setChecked(True)
      self.rdbtnStripped.setBaseSize(10, 10)
      lblStripped = QRichLabel('<b>Stripped Recovery</b><br>'
                               'Only attempts to recover the wallet\'s rootkey and chaincode')

      self.rdbtnBare = QRadioButton()
      lblBare = QRichLabel('<b>Bare Recovery</b><br>'
                           'Attempts to recover all private key related data')

      self.rdbtnFull = QRadioButton()
      lblFull = QRichLabel('<b>Full Recovery</b><br>'
                           'Attempts to recover as much data as possible')

      layoutMgmt.addWidget(self.rdbtnStripped, 3, 0)
      layoutMgmt.addWidget(lblStripped, 3, 1)
      layoutMgmt.addWidget(self.rdbtnBare, 4, 0)
      layoutMgmt.addWidget(lblBare, 4, 1)
      layoutMgmt.addWidget(self.rdbtnFull, 5, 0)
      layoutMgmt.addWidget(lblFull, 5, 1)

      self.btnRecover = QPushButton('Recover')
      self.btnCancel  = QPushButton('Cancel')

      layoutMgmt.addWidget(self.btnRecover, 6, 1)
      layoutMgmt.addWidget(self.btnCancel , 6, 2)


      self.setLayout(layoutMgmt)
      self.setWindowTitle('Wallet Recovery Tool')
      self.setMinimumWidth(450)

################################################################################
class DlgBadPath(ArmoryDialog):
   def __init__(self, WalletPath, parent=None, main=None):
      super(DlgSettings, self).__init__(parent, main)
      
      lblDesc = QRichLabel('<b>Invalid Path</b><br>'
                           'The path you have provided doesn\'t point to an existing file,<br>' 
                           'or the file is not a valid Armory Wallet<br>'
                           'path: %s' % (WalletPath))  
      
      self.btnOk = QPushButton("Ok")
      self.connect(self.btnOk, SIGNAL('clicked()'), self.accept)
      
      layoutMgmt = QGridLayout()
      layoutMgmt.addWidget(lblDesc, 0, 0, 1, 2)
      layoutMgmt.addWidget(self.btnOk, 1, 0)
                      
      self.setLayout(layoutMgmt)
      self.setWindowTitle('Invalid Path')              

#################################################################################


"""
TODO: setup an array of tests:
1) Gaps in chained address entries
2) broken header
3) oversized comment entries
4) comments for non existant addr or txn entries
5) broken private keys, both imported and chained
6) missing private keys with gaps in chain

possible wallet corruption vectors:
1) PyBtcAddress.unlock verifies consistency between private and public key, unless SkipCheck is forced to false. Look for this scenario
2) Imported private keys: is it possible to import private keys to a locked wallet?
3) What happens when an imported private key is sneaked in between a batch of chain addresses? What if some of the private keys aren't computed yet?
"""

#testing it
rcwallet = PyBtcWalletRecovery()
rcwallet.RecoverWallet('/home/goat/Documents/code n shit/watchonly_online_wallet.wallet', 'tests', Mode='Full')
#rcwallet.RecoverWallet('/home/goat/Documents/code n shit/armory_2xCsrj61m_.watchonly.restored_from_paper.wallet', 'tests', Mode='Full')