from armoryengine import *

class PyBtcWalletRecovery(object):
   """
   Fail safe wallet recovery tool. Reads a wallet, verifies and extracts sensitive data to a new file.
   
   """
   
#############################################################################
   
   def RecoverWallet(self, WalletPath, Passphrase, Mode='Bare'):
      """
      Modes: 
         1) Stripped: Only recover the root key and chaincode (it all sits in the header). As fail safe as it gets.
         
         2) Bare: Recover root key, chaincode and matching private/public key pairs. Verify integrity of the wallet and consistency of all entries encountered.
            Skips comments, unprocessed public keys and otherwise corrupted data without attempting to fix it.
         
         3) Full: Recovers as much data as possible from the wallet.

      """

      rmode = 2
      if Mode == 'Stripped': rmode = 1
      elif Mode == 'Full': rmode = 3
         
      LOGWARN('Started recovery of wallet: %s' % (WalletPath))
      TimerStart('Recover Wallet')
      if not os.path.exists(WalletPath):
         raise FileExistsError, "No wallet file:"+WalletPath
      
      toRecover = PyBtcWallet()
      toRecover.walletPath = WalletPath
   
   #consistency check
      try:
         LOGWARN('starting consistency check')
         nError = toRecover.doWalletFileConsistencyCheck()
         LOGWARN('consistency check succesful')
      except KeyDataError, errmsg:
         LOGEXCEPT('***ERROR:  Wallet file had unfixable errors: %s' % (errmsg))
    
    #fetch wallet content  
      LOGWARN('reading wallet')
      wltfile = open(WalletPath, 'rb')
      wltdata = BinaryUnpacker(wltfile.read())
      wltfile.close()
      LOGWARN('read successful')
      
    #check header
      LOGWARN('unpacking header')
      try:
         self.unpackHeader(toRecover, wltdata)
      except err, msg:
         LOGERR('unpack header failed: %s' % (msg))
         return -3
         
      LOGWARN('header unpacked succesfully')

   #check for private keys (watch only?)
      if toRecover.watchingOnly is True:
         LOGERROR('no private keys in this wallet, aborting')
         return -1
      
   #if the wallet uses encryption, decrypt ROOT and verify it
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
         newAddr = toRecover.addrMap['ROOT'] 
         newAddr.unlock(toRecover.kdfKey)
      except:
         LOGERROR('failed to unlock root key')
         return -2
      
      LOGWARN('root key unlocked succesfully')
      
   #create recovered wallet
      RecoveredWallet = PyBtcWallet()
      newwalletPath = os.path.join(os.path.dirname(toRecover.walletPath), 'armory_%s_RECOVERED.wallet' % (toRecover.uniqueIDB58))
      if os.path.exists(newwalletPath):
         LOGERROR('recovery file already exist!')
         return -3
      
      LOGWARN('creating recovery from root key')
      RecoveredWallet.createNewWallet(newWalletFilePath=newwalletPath, securePassphrase=SecurePassphrase, \
                                      plainRootKey=newAddr.binPrivKey32_Plain, chaincode=newAddr.chaincode, \
                                      doRegisterWithBDM=False, \
                                      shortLabel=toRecover.labelName, longLabel=toRecover.labelDescr)
      LOGWARN('recovery file create successfully')
      
      
      if rmode == 1: RecoveryDone() #stripped recovery, we are done
         
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
            RecoveryDone()
            
         if dtype==WLT_DATATYPE_KEYDATA:
            newAddr = PyBtcAddress()
            newAddr.unserialize(rawData)
            newAddr.walletByteLoc = byteLocation + 21
            # Fix byte errors in the address data
            fixedAddrData = newAddr.serialize()
            if not rawData==fixedAddrData:
               LOGWARN('found byte error in address data')

            if newAddr.useEncryption:
               newAddr.isLocked = True   
               
            #check private key against public key, possibly compute missing ones, depending on the recovery mode            
            keymismatch=0
            """
            0: public key matches private key
            1: public key doesn't match private key
            2: private key is missing
            3: public key is missing
            """
            if not newAddr.hasPrivKey(): keymismatch=2
            elif newAddr.chainIndex <= -2:
               #imported private key
               if newAddr.hasPubKey():
                  if newAddr.isLocked:
                     try:
                        newAddr.unlock(toRecover.kfdKey)
                     except KeyDataError: keymismatch=1
                  elif not CryptoECDSA().CheckPubPrivKeyMatch(newAddr.binPrivKey32_Plain, \
                                            newAddr.binPublicKey65): keymismatch=1
               else: keymismatch=3
            
            else:
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
                     newAddr.unlock(toRecover.kfdKey)
                  except KeyDataError: keymismatch=1
               else: keymismatch=2
               
            
            if keymismacth == 1:
               LOGERROR('private/public key mismatch for %s' % (newAddr.addrStr20))
               newAddr.binPublicKey65 = CryptoECDSA().ComputePublicKey(self.binPrivKey32_Plain)
               keymismatch = 0
            elif keymismatch == 3:
               LOGWARN('missing public key')
               newAddr.binPublicKey65 = CryptoECDSA().ComputePublicKey(self.binPrivKey32_Plain)
               keymismatch = 0   
            
            newAddr.addrStr20 = publicKey65.getHash160()
            toSave = PyBtcAddress()
            toSave = newAddr.copy()
            
            newAddr.lock(toRecover.kdfKey)            
            toRecover.addrMap[hashVal] = newAddr            
            chaindepthDict[newAddr.chainIndex] = hashVal           

            toSave.lock(RecoveredWallet.kdfKey) #lock the address entry with the recovered wallet kdfKey before saving it
            
            if keymismatch == 0:
               try:
                  getAddr = RecoveredWallet.addrMap[hashVal]
               except:
                  #address entry wasn't recomputed, save it in recovered wallet
                  RecoveredWallet.walletFileSafeUpdate([[WLT_DATA_ADD, dtype, toSave.addrStr20, toSave.serialize()]])
            
         elif dtype in (WLT_DATATYPE_ADDRCOMMENT, WLT_DATATYPE_TXCOMMENT):
            try:
               fetchAddr = toRecover.addrMap[hashVal]
            except KeyError:
               LOGWARN('no addr entry matches comment hash')
               
            if rmode == 3: RecoveredWallet.walletFileSafeUpdate([[WLT_DATA_ADD, dtype, hashVal, rawData]])
               
         elif dtype==WLT_DATATYPE_OPEVAL:
            LOGWARN('OP_EVAL not supported in wallet yet')
            pass
         elif dtype==WLT_DATATYPE_DELETED:
            pass
         else:
            LOGERROR('invalid dtype: %d' % (dtype))
            RecoveryDone()   
            
      def RecoveryDone():
         TimerStop('Recovered Wallet')
         LOGWARN('Done recovering')

#############################################################################
  
   def unpackHeader(self, wallet, binUnpacker):
      """
      Unpacking the header information from a wallet file.  See the help text
      on the base class, PyBtcWallet, for more information on the wallet
      serialization.
      """
      wallet.fileTypeStr = binUnpacker.get(BINARY_CHUNK, 8)
      wallet.version     = readVersionInt(binUnpacker.get(UINT32))
      wallet.magicBytes  = binUnpacker.get(BINARY_CHUNK, 4)
   
      # Decode the bits to get the flags
      wallet.offsetWltFlags = binUnpacker.getPosition()
      wallet.unpackWalletFlags(binUnpacker)
   
      # This is the first 4 bytes of the 25-byte address-chain-root address
      # This includes the network byte (i.e. main network, testnet, namecoin)
      wallet.uniqueIDBin = binUnpacker.get(BINARY_CHUNK, 6)
      wallet.uniqueIDB58 = binary_to_base58(wallet.uniqueIDBin)
      wallet.wltCreateDate  = binUnpacker.get(UINT64)
   
      # We now have both the magic bytes and network byte
      if not wallet.magicBytes == MAGIC_BYTES:
         LOGERROR('Requested wallet is for a different blockchain!')
         LOGERROR('Wallet is for:  %s ', BLOCKCHAINS[wallet.magicBytes])
         LOGERROR('ArmoryEngine:   %s ', BLOCKCHAINS[MAGIC_BYTES])
         raise WrongMagicWord, 'Wallet is for %s ', % (BLOCKCHAINS[wallet.magicBytes])
      
      if not wallet.uniqueIDBin[-1] == ADDRBYTE:
         LOGERROR('Requested wallet is for a different network!')
         LOGERROR('Wallet is for:  %s ', NETWORKS[wallet.uniqueIDBin[-1]])
         LOGERROR('ArmoryEngine:   %s ', NETWORKS[ADDRBYTE])
         raise WrongNetwork, 'Wallet is for %s ', % (NETWORKS[wallet.uniqueIDBin[-1]])
   
      # User-supplied description/name for wallet
      wallet.offsetLabelName = binUnpacker.getPosition()
      wallet.labelName  = binUnpacker.get(BINARY_CHUNK, 32).strip('\x00')
   
   
      # Longer user-supplied description/name for wallet
      wallet.offsetLabelDescr  = binUnpacker.getPosition()
      wallet.labelDescr  = binUnpacker.get(BINARY_CHUNK, 256).strip('\x00')
   
      wallet.offsetTopUsed = binUnpacker.getPosition()
      wallet.highestUsedChainIndex = binUnpacker.get(INT64)
   
   
      # Read the key-derivation function parameters
      wallet.offsetKdfParams = binUnpacker.getPosition()
      wallet.kdf = wallet.unserializeKdfParams(binUnpacker)
   
      # Read the crypto parameters
      wallet.offsetCrypto    = binUnpacker.getPosition()
      wallet.crypto = wallet.unserializeCryptoParams(binUnpacker)
   
      # Read address-chain root address data
      wallet.offsetRootAddr  = binUnpacker.getPosition()
   
   
      rawAddrData = binUnpacker.get(BINARY_CHUNK, wallet.pybtcaddrSize)
      wallet.addrMap['ROOT'] = PyBtcAddress().unserialize(rawAddrData)
      fixedAddrData = wallet.addrMap['ROOT'].serialize()
      if not rawAddrData==fixedAddrData:
         LOGWARN('byte error in ROOT')
         #wallet.walletFileSafeUpdate([ \
            #[WLT_UPDATE_MODIFY, wallet.offsetRootAddr, fixedAddrData]])
   
      wallet.addrMap['ROOT'].walletByteLoc = wallet.offsetRootAddr
      if wallet.useEncryption:
         wallet.addrMap['ROOT'].isLocked = True
         wallet.isLocked = True
   
      # In wallet version 1.0, this next kB is unused -- may be used in future
      binUnpacker.advance(1024)      

#############################################################################

rcwallet = PyBtcWalletRecovery()
rcwallet.RecoverWallet('D:\\armorydata2\\armory_LDNWRGYW_.wallet', 'tests')