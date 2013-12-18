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
   def RecoveryDone(self):
      LOGWARN('Done recovering')

   def RecoverWallet(self, WalletPath, Passphrase=None, Mode='Bare', GUI=False):
      """
      Modes:
         1) Stripped: Only recover the root key and chaincode (it all sits in the header). As fail safe as it gets.

         2) Bare: Recover root key, chaincode and valid private/public key pairs. Verify integrity of the wallet and consistency of all entries encountered.
            Skips comments, unprocessed public keys and otherwise corrupted data without attempting to fix it.

         3) Full: Recovers as much data as possible from the wallet.

      """

      rmode = 2
      if Mode == 'Stripped' or Mode == 1: rmode = 1
      elif Mode == 'Full' or Mode == 3: rmode = 3

      LOGWARN('Started recovery of wallet: %s' % (WalletPath))
      if not os.path.exists(WalletPath):
         if GUI:
            self.BadPath(WalletPath)
            return
         else:
            raise FileExistsError, 'no such wallet file at given path: ' + WalletPath

      toRecover = PyBtcWallet()
      toRecover.walletPath = WalletPath

   #consistency check
      try:
         LOGWARN('starting consistency check')
         toRecover.doWalletFileConsistencyCheck()
         LOGWARN('consistency check successful')
      except KeyDataError, errmsg:
         LOGEXCEPT('***ERROR:  Wallet file had unfixable errors: %s' % (errmsg))

   #TODO: stronger checks on the path fed

   #fetch wallet content
      LOGWARN('reading wallet')
      wltfile = open(WalletPath, 'rb')
      wltdata = BinaryUnpacker(wltfile.read())
      wltfile.close()
      LOGWARN('read successful')

   #check header
      LOGWARN('unpacking header')
      returned = toRecover.unpackHeader(wltdata)
      if returned < 0:
         LOGERROR('unpack header failed')
         return -3

      LOGWARN('header unpacked successfully')

   #check for private keys (watch only?)
      if toRecover.watchingOnly is True:
         LOGWARN('no private keys in this wallet, checking for chain consistency')
      else:
      #check if wallet is encrypted
         if toRecover.isLocked==True and Passphrase==None:
            #locked wallet and no passphrase, prompt the user
            self.AskUnlock()

         newAddr = toRecover.addrMap['ROOT']

      #if the wallet uses encryption, unlock ROOT and verify it
         if toRecover.isLocked:
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
         RecoveredWallet = PyBtcWallet()
         if rmode > 1: RecoveredWallet.addrPoolSize = toRecover.addrPoolSize #dont rebuild the address chain in stripped mode
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

      #compute address chain
         RecoveredWallet.fillAddressPool(doRegister=False)

         if rmode == 1: self.RecoveryDone() #stripped recovery, we are done

      addrid = 0
      WOaddrDict = {}
      PrevWOAddr = PyBtcAddress()
      addrChainList = []
   #move on to wallet body
      chaindepthDict = {}
      toRecover.lastComputedChainIndex = -UINT32_MAX
      toRecover.lastComputedChainAddr160  = None
      LOGWARN('Now parsing')
      while wltdata.getRemainingSize()>0:
         byteLocation = wltdata.getPosition()
         LOGWARN('At offset: %d' % (byteLocation))

         try:
            dtype, hashVal, rawData = toRecover.unpackNextEntry(wltdata)
         except:
            LOGERROR('Unpack error')
            self.RecoveryDone()

         if dtype==WLT_DATATYPE_KEYDATA:
            addrid = addrid +1
            newAddr = PyBtcAddress()
            newAddr.unserialize(rawData)
            newAddr.walletByteLoc = byteLocation + 21
            # Fix byte errors in the address data
            fixedAddrData = newAddr.serialize()
            if not rawData==fixedAddrData:
               LOGWARN('found byte error in address data')

            if newAddr.useEncryption:
               newAddr.isLocked = True

            addrChainList[addrid] = newAddr.chainIndex

            #if it's a watch only wallet, check for chained addresses consistency
            if toRecover.watchingOnly:
               WOaddrDict[newAddr.chainIndex] = newAddr

               #if newAddr.chainIndex>1:
                  #nextWOaddr = PrevWOAddr.extendAddressChain(None)
                  #if nextWOaddr.binPublicKey65 != newAddr.binPublicKey65:
                  #LOGWARN('index %d, chainIndex %d' % (addrid, newAddr.chainIndex))
                  #LOGWARN('inconsistency in the public address chain found at index %d:' % (addrid))

               #PrevWOAddr = PyBtcAddress()
               #PrevWOAddr = newAddr.copy()

            else:
               #check private key against public key, possibly compute missing ones, depending on the recovery mode
               keymismatch=0
               """
               0: public key matches private key
               1: public key doesn't match private key
               2: private key is missing
               3: public key is missing
               """
               if not newAddr.hasPrivKey():
                  keymismatch=2

                  if newAddr.chainIndex >= 0:
                     #chained private key
                     checkKey=1
                     if newAddr.createPrivKeyNextUnlock:
                        if rmode < 3: checkKey=0
                        else:
                           #have to build the private key on unlock, look for the closest private key to chain off of
                           for i in xrange(newAddr.chainIndex -1, 0):
                              try:
                                 prevHash = chaindepthDict[i]
                                 if toRecover.addrMap[prevHash].createPrivKeyNextUnlock:
                                    newAddr.createPrivKeyNextUnlock_IVandKey[0] = toRecover.addrMap[prevHash].binInitVect16.copy()
                                    newAddr.createPrivKeyNextUnlock_IVandKey[1] = toRecover.addrMap[prevHash].binPrivKey32_Encr.copy()

                                    newAddr.createPrivKeyNextUnlock_ChainDepth = newAddr.chainIndex - toRecover.addrMap[prevHash].chainIndex
                                    break

                              except KeyError:
                                 continue

                     if checkKey == 1:
                        try:
                           """
                           TODO: unlock computes missing chained private keys. This shouldn't be necessary with unencrypted wallets.
                           For now report on missing chained private keys in unencrypted wallets if by any chance the code runs into one
                           To cover all bases, the chaining of private keys should be added for unencrypted addrMap entries
                           """
                           newAddr.unlock(toRecover.kdfKey)
                        except KeyDataError: keymismatch=1
                     else: keymismatch=2

               elif newAddr.chainIndex <= -2:
                     #imported private key
                     if newAddr.hasPubKey():
                        if newAddr.isLocked:
                           try:
                              newAddr.unlock(toRecover.kfdKey)
                           except KeyDataError: keymismatch=1

                        #unlock checks for private/public key matching, so we only have to check for it if the private key isn't locked
                        elif not CryptoECDSA().CheckPubPrivKeyMatch(newAddr.binPrivKey32_Plain, \
                                                  newAddr.binPublicKey65): keymismatch=1

                     else: keymismatch=3

               #TODO: if we're doing a full wallet recovery, fill in missing chainIndex address entries (possibly missing from corruption)

               if keymismatch == 0:
                  if newAddr.isLocked: newAddr.unlock(toRecover.kdfKey)
               elif keymismatch == 1:
                  LOGERROR('private/public key mismatch for %s' % (newAddr.addrStr20))
                  newAddr.binPublicKey65 = CryptoECDSA().ComputePublicKey(self.binPrivKey32_Plain)
                  keymismatch = 0
               elif keymismatch == 3:
                  LOGWARN('missing public key')
                  newAddr.binPublicKey65 = CryptoECDSA().ComputePublicKey(self.binPrivKey32_Plain)
                  keymismatch = 0
               elif keymismatch == 2:
                  LOGWARN('missing imported private key')
                  pass

               newAddr.addrStr20 = newAddr.binPublicKey65.getHash160()
               toSave = PyBtcAddress()
               toSave = newAddr.copy()

               if newAddr.addrStr20 != hashVal:
                  LOGWARN('key pair hash160 doesnt match the hashVal it was saved under!')

               if newAddr.useEncryption:
                  newAddr.lock(toRecover.kdfKey)
                  toSave.lock(RecoveredWallet.kdfKey) #lock the address entry with the recovered wallet kdfKey before saving it

               toRecover.addrMap[newAddr.addrStr20] = newAddr
               chaindepthDict[newAddr.chainIndex] = newAddr.addrStr20

               if keymismatch == 0:
                  try:
                     getAddr = RecoveredWallet.addrMap[newAddr.addrStr20]
                  except:
                     #address entry wasn't computed as part of the first 100 indexes, save it in the recovered wallet
                     RecoveredWallet.walletFileSafeUpdate([[WLT_UPDATE_ADD, dtype, toSave.addrStr20, toSave]])

         elif dtype in (WLT_DATATYPE_ADDRCOMMENT, WLT_DATATYPE_TXCOMMENT):
            try:
               fetchAddr = toRecover.addrMap[hashVal]
            except KeyError:
               LOGWARN('no address entry matches comment hash')

            if rmode == 3: RecoveredWallet.walletFileSafeUpdate([[WLT_UPDATE_ADD, dtype, hashVal, rawData]])

         elif dtype==WLT_DATATYPE_OPEVAL:
            LOGWARN('OP_EVAL not supported in wallet yet')
            pass
         elif dtype==WLT_DATATYPE_DELETED:
            pass
         else:
            LOGERROR('invalid dtype: %d' % (dtype))
            self.RecoveryDone()

   #done
      test = 3
      if toRecover.watchingOnly and test==1:
         #inspect WO address entries
         prevAddr = PyBtcAddress()
         prevAddr = WOaddrDict[0]
         for i in range(1, addrid):
            currAddr = PyBtcAddress()
            currAddr = WOaddrDict[i]
            extdAddr = prevAddr.extendAddressChain(None)

            if currAddr.addrStr20 != extdAddr.addrStr20:
               LOGWARN('address inconsistency at index: %d' % (i))

            prevAddr = currAddr

      if toRecover.watchingOnly and test==2:
         prevAddr = PyBtcAddress()
         prevAddr = WOaddrDict[7298]
         prevAddrChaincode = prevAddr.chaincode.toHexStr()
         for i in range(0, addrid):
            currAddr = PyBtcAddress()
            currAddr = WOaddrDict[i]
            extdAddr = currAddr.extendAddressChain(None)
            currAddrChaincode = currAddr.chaincode.toHexStr()

            if currAddrChaincode != prevAddrChaincode:
               LOGWARN('unconsistent chaincode')
            if prevAddr.addrStr20 == extdAddr.addrStr20:
               LOGWARN('address inconsistency fixed with: %d' % (i))

            #prevAddr = currAddr

      if toRecover.watchingOnly and test==3:
         prevAddr = PyBtcAddress()
         prevAddr = WOaddrDict[7298]
         prevAddrChaincode = prevAddr.chaincode.toHexStr()

         abc = CryptoECDSA().VerifyPublicKeyValid(prevAddr.binPublicKey65)
         if abc:
            abc = abc +1

      if toRecover.watchingOnly and test==4:
         prevAddr = PyBtcAddress()
         prevAddr = WOaddrDict[7297]
         prevAddrChaincode = prevAddr.chaincode.toHexStr()

         #start =
         #for i in range (0, 256):

            #prevAddrChaincodeFlipped =

      self.RecoveryDone()

   #############################################################################
   #GUI related members start here
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

#############################################################################
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