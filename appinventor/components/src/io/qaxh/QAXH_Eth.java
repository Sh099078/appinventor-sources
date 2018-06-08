// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2009-2011 Google, All Rights reserved
// Copyright 2011-2012 MIT, All rights reserved
// Released under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

package io.qaxh.eth;

import com.google.appinventor.components.runtime.Component;
import com.google.appinventor.components.runtime.AndroidNonvisibleComponent;
import com.google.appinventor.components.runtime.ComponentContainer;

//import org.web3j.protocol.infura.InfuraHttpService;
import org.web3j.protocol.http.HttpService;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.Web3jFactory;
import org.web3j.protocol.core.methods.response.EthAccounts;
import org.web3j.protocol.core.methods.response.EthBlock;
import org.web3j.protocol.core.methods.response.EthBlockNumber;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthCoinbase;
import org.web3j.protocol.core.methods.response.EthCompileLLL;
import org.web3j.protocol.core.methods.response.EthCompileSerpent;
import org.web3j.protocol.core.methods.response.EthCompileSolidity;
import org.web3j.protocol.core.methods.response.EthEstimateGas;
import org.web3j.protocol.core.methods.response.EthFilter;
import org.web3j.protocol.core.methods.response.EthGasPrice;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.EthGetBlockTransactionCountByHash;
import org.web3j.protocol.core.methods.response.EthGetBlockTransactionCountByNumber;
import org.web3j.protocol.core.methods.response.EthGetCode;
import org.web3j.protocol.core.methods.response.EthGetCompilers;
import org.web3j.protocol.core.methods.response.EthGetStorageAt;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthGetTransactionReceipt;
import org.web3j.protocol.core.methods.response.EthGetUncleCountByBlockHash;
import org.web3j.protocol.core.methods.response.EthGetUncleCountByBlockNumber;
import org.web3j.protocol.core.methods.response.EthHashrate;
import org.web3j.protocol.core.methods.response.EthLog;
import org.web3j.protocol.core.methods.response.EthMining;
import org.web3j.protocol.core.methods.response.EthProtocolVersion;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.EthSyncing;
import org.web3j.protocol.core.methods.response.EthTransaction;
import org.web3j.protocol.core.methods.response.EthUninstallFilter;
import org.web3j.protocol.core.methods.response.NetListening;
import org.web3j.protocol.core.methods.response.NetPeerCount;
import org.web3j.protocol.core.methods.response.NetVersion;
import org.web3j.protocol.core.methods.response.ShhNewGroup;
import org.web3j.protocol.core.methods.response.ShhNewIdentity;
import org.web3j.protocol.core.methods.response.ShhVersion;
import org.web3j.protocol.core.methods.response.Transaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.core.methods.response.Web3ClientVersion;
import org.web3j.protocol.core.methods.response.Web3Sha3;
import org.web3j.utils.Numeric;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.DefaultBlockParameterNumber;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Hash;
import org.web3j.tx.RawTransactionManager;
import org.web3j.utils.Convert;


import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.jcajce.provider.digest.Keccak;


import java.security.SecureRandom;
import java.security.Security;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.InvalidKeyException;

// need proper version of jar file
//import android.security.keystore.KeyProperties;

import com.google.appinventor.components.annotations.DesignerProperty;
import com.google.appinventor.components.annotations.DesignerComponent;
import com.google.appinventor.components.annotations.PropertyCategory;
import com.google.appinventor.components.annotations.SimpleEvent;
import com.google.appinventor.components.annotations.SimpleFunction;
import com.google.appinventor.components.annotations.SimpleObject;
import com.google.appinventor.components.annotations.SimpleProperty;
import com.google.appinventor.components.annotations.UsesLibraries;
import com.google.appinventor.components.common.ComponentCategory;
import com.google.appinventor.components.common.PropertyTypeConstants;
import com.google.appinventor.components.common.YaVersion;
import com.google.appinventor.components.runtime.util.ErrorMessages;

import rx.Subscription;

import android.graphics.Bitmap;
import android.graphics.Color;
import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.net.Uri;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.Locale;
import java.math.BigInteger;
import java.util.Formatter;

import java.lang.Throwable;


@DesignerComponent(version = YaVersion.QAXH_ETH_COMPONENT_VERSION,
   description = "This component implements ethereum access.",
   category = ComponentCategory.EXTENSION,
   nonVisible = true,
   iconName = "aiwebres/eth.png")
@SimpleObject(external=true)
@UsesLibraries(libraries = 
	       "core-3.3.1-android.jar, "+
	       "crypto-3.3.1-android.jar, "+
	       "utils-3.3.1-android.jar, "+
	       "rlp-3.3.1-android.jar, "+
	       "tuples-3.3.1-android.jar, "+
	       "abi-3.3.1-android.jar, "+
	       "slf4j-api-1.7.25.jar, "+
	       "okio-1.14.1.jar, "+
	       "javapoet-1.7.0.jar, "+
	       "okhttp-3.10.0.jar, "+
	       "rxjava-1.2.2.jar, "+
	       "jackson-core-2.1.3.jar, " +
	       "jackson-databind-2.1.3.jar, "+
	       "jackson-annotations-2.1.4.jar, "+
	       "scrypt-1.4.0.jar, "+
	       "prov-1.54.0.0.jar, "+
	       "core-1.54.0.0.jar")
public class QAXH_Eth extends AndroidNonvisibleComponent implements Component {
  
  private static final String LOG_TAG = "QaxhEthComponent";

  Web3j web3;

  /**
   * Creates a QAXH_Eth component.
   *
   * This function isn't visible from AppInventor.
   *
   * @param container container, component will be placed in
   */
  public QAXH_Eth(ComponentContainer container) {
     super(container.$form());
     //      initializeWeb3();
    Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
  }

  /**
   * Give the keccak hash of a string
   *
   * @param String message, message to hash
   */
  @SimpleFunction(
    description = "Computes the Keccak-256 of the string parameter.")
    public String keccak(String message) {
    return Hash.sha3(message);
  }

/**
* Get a 128 bits random number
*
* @return a 128 bits random number
*/
 @SimpleFunction(
    description = "Get a 128 bits random number")
    public String getRandom128(){
    SecureRandom rng = new SecureRandom();
    byte[] randomBytes = new byte[16];

    rng.nextBytes(randomBytes);
    return bytesToHex(randomBytes);
}

/**
* Get a 256 bits random number
*
* @return a 256 bits random number
*/
 @SimpleFunction(
    description = "Get a 256 bits random number")
    public String getRandom256(){ 
    SecureRandom rng = new SecureRandom();
    byte[] randomBytes = new byte[32];

    rng.nextBytes(randomBytes);
    return bytesToHex(randomBytes);
}
  
private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

/**
 * Convert from bytes to hexadecimal
 *
 * This function isn't visible from AppInventor.
 *
 * @param byte[] bytes, the array of bits to be translated
 * @return a string containing the transalation in hexadecimal
 */
private static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for ( int j = 0; j < bytes.length; j++ ) {
        int v = bytes[j] & 0xFF;
        hexChars[j * 2] = hexArray[v >>> 4];
        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
}
 
 /**
 * Gets the client version from infura.
 *
 * @return the client version from infura.
 */
  @SimpleFunction(
		  description = "Gets the client version from infura.")
		  public String getClientVersion(){
    initializeWeb3();
    String clientVersion;
    Web3ClientVersion web3ClientVersion;
    try {
      web3ClientVersion = web3.web3ClientVersion().send();
    }
    catch(IOException e) {
      return "Could not get version: could not reach network";
    }
    clientVersion = web3ClientVersion.getWeb3ClientVersion();
    return clientVersion;
  }  

/**
* Gets the current block number.
*
* @return the current block number.
*/
@SimpleFunction(
		  description = "Gets the current block number.")
		  public String getBlockNumber(){
    initializeWeb3();
    EthBlockNumber ethBlockNumber;
    Web3ClientVersion web3ClientVersion;
    try {
      ethBlockNumber = web3.ethBlockNumber().send();
    }
    catch(IOException e) {
      return "couldn reach network";
    }
    return ethBlockNumber.getBlockNumber().toString();
  }

/**
 * Gets the balance of an account.
 *
 * @param String account, hexadecimal id of the account
 * @return the balance of the account which id was passed in parameter.
 */
@SimpleFunction(
		  description = "Gets the balance of an account.")
public String getBalance(String account){
    initializeWeb3();
    EthGetBalance ethGetBalance;
    try {
      ethGetBalance = web3.ethGetBalance(
					 account.toUpperCase(Locale.US), DefaultBlockParameterName.LATEST).send();
    }
    catch(IOException e) {
      return "Could not reach network";
    }
    return ethGetBalance.getBalance().toString();
  }

  /**
   * Generates and ethereum private/public key pair.
   *
   * @return the keys and address of the account, in format : Ox <privateKey> /0x04 <publicKeys> /Ox <adress>
   */
    @SimpleFunction (
		     description = "Generates and ethereum private/public key pair.")
		     public String getKeyPair() {
    ECPublicKey        publicKey;
    ECPrivateKey       privateKey;
    BigInteger priv=BigInteger.ZERO;
    ECPoint pubPoint;
    BigInteger pubX=BigInteger.ZERO;
    BigInteger pubY=BigInteger.ZERO;
    boolean oddY=false;
    try {
        ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("secp256k1");
	//KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,"AndroidKeyStore");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA","SC");
        kpg.initialize(ecParamSpec, new SecureRandom());

        KeyPair keyPair=kpg.generateKeyPair();
        publicKey=(ECPublicKey)keyPair.getPublic();
        privateKey=(ECPrivateKey)keyPair.getPrivate();
    	priv=privateKey.getS();
    	pubPoint=publicKey.getW();
    	pubX=pubPoint.getAffineX();
    	pubY=pubPoint.getAffineY();
	oddY = pubY.testBit(0);
    }catch(Exception e){
	    e.printStackTrace();
    }
    return "0x" + priv.toString(16) + "/0x04" + pubX.toString(16) +  pubY.toString(16) + "/0x" + Keys.getAddress(pubX.toString(16) + pubY.toString(16));
  }
  /*
  @SimpleFunction (
		   description = "Stores the private key in the keystore")
		   public boolean storePrivate(String keyPrivate, String password) {
    KeyStore ks = KeyStore.getInstance("SC");

    KeyStore.ProtectionParameter protParam =
      new KeyStore.PasswordProtection(password);

    ECParameterSpec spec = new ECGenParameterSpec("secp256k1");

    ECPrivateKeySpec sKeySpec = new ECPrivateKeySpec(
						   new BigInteger(keyPrivate,16),
            spec);

    KeyFactory fact = KeyFactory.getInstance("ECDSA", "SC");

    PrivateKey sKey = fact.generatePrivate(sKeySpec);
    KeyStore.SecretKeyEntry skEntry =
        new KeyStore.SecretKeyEntry(sKey);
    ks.setEntry("QAXH", skEntry, protParam);
  }

    @SimpleFunction (
		   description = "Retreives the private key from the keystore")
		   public boolean retrievePrivate(String keyPrivate, String password) {
    KeyStore ks = KeyStore.getInstance("SC");

    KeyStore.ProtectionParameter protParam =
      new KeyStore.PasswordProtection(password);

    KeyStore.SecretKeyEntry skEntry=ks.getEntry("QAXH",protParam);
    //ECPrivateKey priv=(ECPrivateKey) skEntry;
    
    ECParameterSpec spec = new ECGenParameterSpec("secp256k1");

    }
  */

  /**
   * Get jose acc1 private key
   *
   * @return jose acc1 private key
   */
  @SimpleFunction (
		   description = "Get jose acc1 private key")
		   public String getMyPrivateKey1 () {
    return "0x14ebf22bed393fba2f7ccb8b066e0def213a4ffb4104cb857c93f77aee81fb80";
    // clem : fa3ec1fbb708a16c8ff989831b4fb08d9b8f008605e55cb35f19a5f430939483
  }

  /**
   * Get jose acc1 address
   *
   * @return jose acc1 address
   */
  @SimpleFunction (
		   description = "Get jose acc1 address")
		   public String getMyAddress1 () {
    return "0xcffecd1800c4a713f69BF0980c810a67452f999f";
    // clem : 0x210053ed365203a6a8F3983F7823B4326Fd1F9D7
  }
  
  /**
   * Get jose acc2 private key
   *
   * @return jose acc2 private key
   */
  @SimpleFunction (
		   description = "Get jose acc2 private key")
		   public String getMyPrivateKey2 () {
    return "0xee0acd09f8d473486f06d800e8b04ad94ea89f6e59fb4e6bf22cd167be751f1b";
  }

  /**
   * Get jose acc2 address
   *
   * @return jose acc2 address
   */
  @SimpleFunction (
		   description = "Get jose acc2 address")
		   public String getMyAddress2 () {
    return "0x29556bD6CAe91793085C16eDa4A23d24403b26c3";
  }
  
  /**
   * Get jose acc3 private key
   *
   * @return jose acc3 private key
   */
  @SimpleFunction (
		   description = "Get jose acc3 private key")
		   public String getMyPrivateKey3 () {
    return "0x53493e1b418b3ebc112c55fb76d67a9027148d8202011c64776020819f4e4c79";
  }

    /**
     * Get jose acc3 address
     *
     * @return jose acc3 address
     */
    @SimpleFunction (
		   description = "Get jose acc3 address")
		   public String getMyAddress3 () {
    return "0x4b5b3f3c90abb0f9421ff3839dceab9ac2189013";
  }
  
  /**
   * Send Gwei = 10-9 ether.
   *
   * @param String privKeyHex, the private key of the sending account in hexadecimal
   * @param String dest, the address of the receiver in hexadecimal
   * @param String howMuchGwei, number of Gwei to send
   * @param String data, the data to encript in the transaction, usually the identity hash here
   * @return the transaction hash if successful, if not a String Error : with an explaination of why it failed.
   */
  @SimpleFunction (
		   description = "Send Gwei = 10-9 ether.")
		   public String sendGwei(String privKeyHex,String dest, String howMuchGwei,String data)
  {
    Credentials credentials = Credentials.create(privKeyHex);
    initializeWeb3();

    RawTransactionManager rawTM = new RawTransactionManager(web3,credentials);
    
    BigInteger howMuchWei = Convert.toWei(howMuchGwei, Convert.Unit.GWEI).toBigInteger();
    BigInteger gasLimit = BigInteger.valueOf(4800000);
    EthSendTransaction sentTransaction;
    EthGetTransactionReceipt ethTransactionReceipt=null;
    String transactionHash;
    int iterations=0;
    try {
      BigInteger gasPrice = web3.ethGasPrice().send().getGasPrice();
      //gasPrice = gasPrice.shiftLeft(1);
      sentTransaction=rawTM.sendTransaction(gasPrice,gasLimit,
					    dest,data,howMuchWei);
      transactionHash = sentTransaction.getTransactionHash();

      if (transactionHash == null || transactionHash.isEmpty()) {
	return "Error: failed to send transaction. \n"
            "Error message : " + sentTransaction.getError().getMessage() ;
      }
    } catch (IOException e) {
	  return "Error: failed to send transaction, could not reach network";
    }

    return transactionHash;
  }
  /*
    @SimpleFunction(
		  description = "List transactions from an address")
		  public String getTransactionsFromAddress(String address_0x, String fromBlock) {
      String result="";
      web3=Web3jFactory.build(new HttpService("https://rinkeby.infura.io/MCLIpiMOeM176U6zBTT5"));
      BigInteger biFromBlock = new BigInteger(fromBlock);
      Subscription subscription =
	web3.replayTransactionsObservable(new DefaultBlockParameterNumber(biFromBlock),
					  new DefaultBlockParameterNumber(biFromBlock.add(BigInteger.valueOf(100))))
	.filter(tx -> tx.getFrom().equals(address_0x))
	.subscribe(tx -> result.concat(tx.getValue().toString() + ";"),Throwable::printStackTrace);
  //	.doOnError(throwable -> Log.d(LOG_TAG,"Error occurred" + throwable.printStackTrace));

      subscription.unsubscribe();
      return result;
  }
  */

/**
 * Build a Web3j object to access to the blockchain, if one wasn't created before.
 *
 * This function isn't visible from AppInventor.
 */
  void initializeWeb3() {
    if (web3 == null) {
      web3=Web3jFactory.build(new HttpService("https://rinkeby.infura.io/MCLIpiMOeM176U6zBTT5"));
//InfuraHttpService
    }
  }

/**
 * Get the status of a transaction
 *
 * @param String transactionId, the hexadecimal id of the transaction to scan
 * @return a String, describing the status if successful, with a Error : + explanation if not.
 */
@SimpleFunction(
        description = "Get the status of a transaction")
public String getTransactionStatus(String transactionId) {

    initializeWeb3();
    EthTransaction ethTx;
    try {
        ethTx=web3.ethGetTransactionByHash(transactionId).send();
    } catch(IOException e) {
        return "Error: Could not find transaction: could not reach network";
    }

    EthGetTransactionReceipt ethTxReceipt = null;

    try {
        ethTxReceipt = web3.ethGetTransactionReceipt(transactionId).sendAsync().get();
    }
    catch (Exception e) {
        return "failed to poll status for transaction " + transactionId;
    }
    TransactionReceipt txReceipt = ethTxReceipt.getTransactionReceipt();
    if (txReceipt == null) {
        return "Pending";
    }
    if (txReceipt.getStatus().equals("0x1")) {
        return String.format("Mined in block#" + txReceipt.getBlockNumberRaw() + "Gas used: %d",txReceipt.getGasUsed());
    }

    return String.format(
            "Transaction has failed with status: %s. "
                    + "Gas used: %d. (not-enough gas?)",
            txReceipt.getStatus(),
            txReceipt.getGasUsed());
}
  
  /**
   * Checks if the account hash has been registered in a transaction.
   *
   * To be correst, the transaction must have been send by the user which adress is specified,
   * and with a data which is the same as the specified hash (identy check).
   *
   * @param String transaction_0x, the hexadecimal id of a transaction
   * @param String address, an hexadecimal address
   * @param String hash, an identity hash (typically corresponding to the address before)
   * @return OKHASH or Wrong hash. Error if the network isn't reacheable.
   */
  @SimpleFunction(
		  description = "Checks if the account hash has been registered in a transaction")
      public String isValidQaxhAccountHash(String transaction_0x, String address, String hash) {
      initializeWeb3();
      EthTransaction ethTx;
      try {
	ethTx=web3.ethGetTransactionByHash(transaction_0x).send();
      } catch(IOException e) {
	return "Error: Could not find transaction: could not reach network";
      }
      Transaction tx = ethTx.getTransaction();
      
      String blockHash = tx.getBlockHash();
      BigInteger blockNumber = tx.getBlockNumber();
      String from = tx.getFrom();
      String to = tx.getTo();
      BigInteger amount = tx.getValue();
      String inputData = tx.getInput();
      if (from.equalsIgnoreCase(address) && inputData.equalsIgnoreCase(hash)){
	return "OKHASH";
      } else {
	return "Error: Wrong hash";
      }
  }
  
  /**
   * Retrieves all the details in a transaction
   *
   * @param String transaction_0x, the hexadecimal id of a transaction
   * @return if the network is reachable : a String with the block, sender, receiver, amount and date; if not, a String Error.
   */
  @SimpleFunction(
		  description = "Retrieves all the details in a transaction")
      public String getTransactionDetails(String transaction_0x) {
      initializeWeb3();
      EthTransaction ethTx;
      try {
	ethTx=web3.ethGetTransactionByHash(transaction_0x).send();
      } catch(IOException e) {
	return "Error: Could not find transaction: could not reach network";
      }
      Transaction tx = ethTx.getTransaction();

      String blockHash = tx.getBlockHash();
      BigInteger blockNumber = tx.getBlockNumber();
      String from = tx.getFrom();
      String to = tx.getTo();
      BigInteger amount = tx.getValue();
      String inputData = tx.getInput();

      return "Block#" + blockNumber.toString() + " From:" + from + " To:" + to +
	" Amount:" + amount.toString() + " InputData:" + inputData;
  }

}
