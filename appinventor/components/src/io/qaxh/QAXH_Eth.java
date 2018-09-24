// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2009-2011 Google, All Rights reserved
// Copyright 2011-2012 MIT, All rights reserved
// Released under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

package io.qaxh.eth;

import io.qaxh.etherscan.Etherscan;

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
import org.web3j.protocol.core.methods.response.EthBlock;
import org.web3j.protocol.core.methods.response.EthBlock.TransactionResult;
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
import org.web3j.tx.ManagedTransaction;


import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.crypto.ECKeyPair;


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
import com.google.appinventor.components.runtime.util.YailList;

import rx.Subscription;
import rx.functions.Action1;

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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Arrays;
import java.util.Dictionary;
import java.io.IOException;

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
        return Hash.sha3String(message);
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
     * Convert ASCII text to hexadecimal
     *
     * @param text in ASCII
     * @return a String encoding the text passed in parameter in hexadecimal
     */
    @SimpleFunction(
            description = "Convert from ASCII to hexadecimal")
    public String ASCIItoHex(String text) {
        try {
            return String.format("0x%x", new BigInteger(1, text.getBytes("UTF-8")));
        } catch (java.io.UnsupportedEncodingException e) {
            return "Not possible to convert to hex with the current parameters.";
        }
    }

    /**
     * Convert hexadecimal to ASCII
     *
     * @param hex, a String encoded in hexadeciam
     * @return hex translated in ASCII
     */
    @SimpleFunction(
            description = "Convert from hexadecimal to ASCII")
    public String HextoASCII(String hex) {
        hex = hex.substring(2, hex.length());
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i+=2) {
            String str = hex.substring(i, i+2);
            output.append((char)Integer.parseInt(str, 16));
        }
        return output.toString();
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
        //gasLimit = gasLimit.multiply(BigInteger.valueOf(1000));
        EthSendTransaction sentTransaction;
        //EthGetTransactionReceipt ethTransactionReceipt=null;
        String transactionHash;
        //int iterations=0;
        try {
            BigInteger gasPrice = web3.ethGasPrice().send().getGasPrice();
            gasPrice = gasPrice.multiply(BigInteger.valueOf(2)); //to make it faster
            //BigInteger gasPrice = BigInteger.valueOf(1);
            sentTransaction=rawTM.sendTransaction(gasPrice,gasLimit,
                    dest,data,howMuchWei);
            transactionHash = sentTransaction.getTransactionHash();

            if (transactionHash == null || transactionHash.isEmpty()) {
                return "Error: failed to send transaction. \n" +
                        "Error message : " + sentTransaction.getError().getMessage();
            }
        } catch (IOException e) {
            return "Error: failed to send transaction, could not reach network";
        }
        return transactionHash;
    }

    /**
     * Build a Web3j object to access to the blockchain, if one wasn't created before.
     *
     * This function isn't visible from AppInventor.
     */
    public void initializeWeb3() {
        if (web3 == null) {
            web3=Web3jFactory.build(new HttpService("https://rinkeby.infura.io/MCLIpiMOeM176U6zBTT5"));
//InfuraHttpService
            //web3=Web3jFactory.build(new HttpService("http://104.155.76.235:8545"));
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

    /******************************************************************************************************************
     ************************************************** STEP 2 ********************************************************
     *****************************************************************************************************************/


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
            description = "Checks if the account hash has been registered in a transaction, from the user point of view")
    public String isValidAccountUserHash(String transaction_0x, String address, String hash) {
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
     * Checks if the A2 transaction (certification of identity by the plateform) exists and has the expected hash.
     *
     * @param String txId1, the hexadecimal id of the 1 transaction for this user
     * @param String hash, the hash that must be found for the 2 transaction
     * @return OKHASH/A2TxId/address or an "Error : *" message
     * where A2TxId is the id of the A2 transaction if found,
     * address the sender of the A2 tx (to be compared later with the known qaxh plateform addresses.
     */
    @SimpleFunction(
            description = "Checks if the A2 transaction exists and has the expected hash.")
    public String isValidAccountQaxhHash(String txId1, String hash2) {

        //get transaction A1 (tx)
        initializeWeb3();
        EthTransaction ethTx;
        try {
            ethTx = web3.ethGetTransactionByHash(txId1).send();
        } catch (IOException e) {
            return "Error: Could not find transaction: could not reach network";
        }
        Transaction tx = ethTx.getTransaction();

        //get current block number
        EthBlockNumber ethBlockNumber;
        Web3ClientVersion web3ClientVersion;
        try {
            ethBlockNumber = web3.ethBlockNumber().send();
        }
        catch(IOException e) {
            return "couldn reach network";
        }
        BigInteger currentBlockNumber = ethBlockNumber.getBlockNumber();

        //initialisation from transaction 1
        String user = tx.getFrom();
        BigInteger one = BigInteger.valueOf( (long) 1);
        BigInteger limit = BigInteger.valueOf( (long) 50);
        Transaction tx2;

        for ( BigInteger i = tx.getBlockNumber() ; i.compareTo( tx.getBlockNumber().add(limit)) < 1 ; i = i.add(one) ) {
            //List<Transaction> listTx;

            List<TransactionResult> listTx;
            try {
                EthBlock ethBlock = web3.ethGetBlockByNumber(new DefaultBlockParameterNumber(i), true).send();
                listTx = ethBlock.getBlock().getTransactions();
                //listTx = getTransactionsFromBlock(i);
            } catch (IOException e) {
                return ("Problem connecting to network");
            }
            for (TransactionResult txR : listTx) {
                tx2 = (Transaction) txR.get();
                if (tx2.getTo() != null ){ //smart contract creation
                    if (toChecksumAddress(tx2.getTo()).equals(toChecksumAddress(user))
                            && tx2.getInput().equals(hash2) ) {
                            return "OKHASH/" + tx2.getHash() + "/" + tx2.getFrom();
                    }

                }
            }
        }

        return "Error : could not find transaction from plateform";

    }

    /*
    /**
     * Initialize the block number to read from when using readReceivedOneBlock.
     *
     * @param String
     */
    /*
    @SimpleFunction(
            description = "Initialize the block number to read from when using readReceivedOneBlock.")
    public void initializeReadBlockNumber(String blockNumber) {

        //initialise currentBlockNum
        currentBlockNum = BigInteger.valueOf( Integer.parseInt(blockNumber) );
    }

    /**
     * DEPRECIATED : USE readReceivedBlock IF POSSIBLE.
     * Retreive all the transactions received by this user, since the last call to this function or the block passed to initializeReadBlockNumber, to now.
     * The initializeReadBlockNumber() function must have been called at least once before.
     * Note that this function CAN in fact pull more than one block, but this name was chosen to illustrate the expected use of the function :
     * it is designed to be called every 15 sec. on the rinkeby testnet. So it should TYPICALLY only pull one block.
     *
     * @param address, the address of the user to retreive received transactions for.
     * @return a list of received transaction, encoded in a String like so : 0x... / 0x... / 0x...
     */
    /*
    @SimpleFunction(
            description = "Retreived all the transactions received by the address, since the last call to this function." +
                    "WARNING : the initializeReadBlockNumber() function must have been called at least once before.")
    public String readReceivedOneBlock(String address) {
        initializeWeb3();

        //get current block number
        EthBlockNumber ethBlockNumber;
        Web3ClientVersion web3ClientVersion;
        try {
            ethBlockNumber = web3.ethBlockNumber().send();
        }
        catch(IOException e) {
            return "couldn reach network";
        }
        BigInteger currentBlockNumber = ethBlockNumber.getBlockNumber();

        //some constants
        BigInteger one = BigInteger.valueOf( (long) 1);
        Transaction tx ;
        String result = "";
        BigInteger temp = currentBlockNum ; //used to increment currentBlockNum at the end of the process

        //search
        for ( BigInteger i = currentBlockNum ; i.compareTo(currentBlockNumber) < 1 ; i = i.add(one) ) {

            List<TransactionResult> listTx;
            try {
                EthBlock ethBlock = web3.ethGetBlockByNumber(new DefaultBlockParameterNumber(i), true).send();
                listTx = ethBlock.getBlock().getTransactions();
            } catch (IOException e) {
                return ("Problem connecting to network");
            }
            for (TransactionResult txR : listTx) {
                tx = (Transaction) txR.get();
                if (tx.getTo() != null) { //smart contract creation
                    if (toChecksumAddress(tx.getTo()).equals(toChecksumAddress(address))) {
                        result += tx.getHash() + "/";
                    }
                }
            }
            temp = i;
        }
        currentBlockNum = temp;

        return result.substring(0, result.length());
    }
    */

    /**
     * Retreive all the transactions received by this user. Begin at the firstBlockNumber block and search for howMuchBlocks blocks.
     *
     * @param address, the address of the user to retreive received transactions for.
     * @param firstBlockNumber, the block umber to start from
     * @param howMuchBlocks, the number of blocks to read
     * @return the last block read / a list of received transaction, encoded in a String
     * ex : the last block read number / 0x... / 0x... / 0x...
     */
    @SimpleFunction(
            description = "Retreived all the transactions received by the address, " +
                    "Begin searching at the block passed in parameters and continue for howMuchBlocks blocks ")
    public String readReceivedBlock(String address, String firstBlockNumber, int howMuchBlocks) {
        initializeWeb3();

        BigInteger blockNumber = BigInteger.valueOf(Integer.parseInt(firstBlockNumber));

        //some constants
        BigInteger one = BigInteger.valueOf( (long) 1);
        Transaction tx ;
        String result = "";
        BigInteger i = blockNumber ;

        //search
        while(i.compareTo(blockNumber.add(BigInteger.valueOf(howMuchBlocks))) == -1 ) {

            List<TransactionResult> listTx;
            try {
                EthBlock ethBlock = web3.ethGetBlockByNumber(new DefaultBlockParameterNumber(i), true).send();
                listTx = ethBlock.getBlock().getTransactions();
            } catch (IOException e) {
                return ("Problem connecting to network");
            }
            for (TransactionResult txR : listTx) {
                tx = (Transaction) txR.get();
                if (tx.getTo() != null) { //smart contract creation
                    if (toChecksumAddress(tx.getTo()).equals(toChecksumAddress(address))) {
                        result += tx.getHash() + "/";
                    }
                }
            }
            i = i.add(one);
        }
        return i.toString() + "/" + result;
    }

    /**
     * Return the address, but "checksummed"
     *
     * @param String address, the address to transform
     * @return String checksum
     */
    @SimpleFunction(
            description = "Checksum the address")
    public String toChecksumAddress(String address) {
        return Keys.toChecksumAddress(address);
    }


    /******************************************************************************************************************
     ****************************************** Using Etherscan API ***************************************************
     *****************************************************************************************************************/

    @SimpleFunction(
            description = "Get the lists of received and sent transaction for an address, using the etherscan API")
    public YailList getTxLists(String address, String startNumber, String endNumber ) {
        Etherscan client = new Etherscan();
        List[] res = new List[2];
        try {
            res = client.main(address, startNumber, endNumber);
        } catch (IOException e) {
            //do nothing
        }
        YailList list = new YailList();
        List<YailList> res2 = new ArrayList<YailList>();
        res2.add(list.makeList(res[0]));
        res2.add(list.makeList(res[1]));
        return list.makeList(res2);
    }



    /******************************************************************************************************************
     ************************************************** STEP 3 ********************************************************
     *****************************************************************************************************************/

    /*
    Dictionary<String,String> contractAdresses = Dictionary<String,String>();
    contractAdresses.put("greeter", "0xd322211f9fec0d98f447532f4b4e063b9fad086c");
    contractAdresses.put("safe.Migrations","0x9913bb2fa5Bbf19132745598Fe4fbC69Ea55E4F6");
    contractAdresses.put("safe.ProxyFactory", "0x57Bdee172f4cDE7ca43A446ED4358cfa6a0C9CC6");
    contractAdresses.put("safe.GnosisSafePersonalEdition", "0x1a311bdc60a33b480d14a80794bc74417ac787aa");
    contractAdresses.put("safe.GnosisSafeTeamEdition", "0xa3f9cf8d1393a5675a759a64cc26a271130b3c14");
    contractAdresses.put("safe.StateChannelModule", "0xa03681c246651b648bfc1f4e59633fbd61713612");
    contractAdresses.put("safe.DailyLimitModule", "0xefd9ae006cf2d69b5c1fa2413ddafaf4039d9259");
    contractAdresses.put("safe.SocialRecoveryModule", "0x8a210fb79d0486fb66eaa79ce57ea96fb746ec7d");
    contractAdresses.put("safe.WhitelistModule", "0x8370677460b333315c966b8939a7edf1af3ac3aa");
    contractAdresses.put("safe.CreateAndAddModules", "0xfa62599d2c0e6f8c3e5fed92631c5adfa340ce04");
    contractAdresses.put("safe.MultiSend", "0xa2863279b121c08b6cb96d6ed4b0906ad23ddd81");

    Dictionary<int,String> ProxyFactory = Dictionary<int,String>();
    ProxyFactory.put(0, "createProxy");
    Dictionary<int,String> GnosisSafePersonalEdition = Dictionary<int,String>(); //flemme
    Dictionary<int,String> GnosisSafeTeamEdition = Dictionary<int,String>(); //flemme
    Dictionary<int,String> StateChannelModule = Dictionary<int,String>();
    StateChannelModule.put(2, "changeMasterCopy");
    StateChannelModule.put(4, "setup");
    StateChannelModule.put(6, "execTransaction");
    Dictionary<int,String> DailyLimitModule = Dictionary<int,String>();
    DailyLimitModule.put(0, "setup");
    DailyLimitModule.put(2, "executeDailyLimit");
    DailyLimitModule.put(3, "changeMasterCopy");
    DailyLimitModule.put(4, "changeDailyLimit");
    Dictionary<int,String> SocialRecoveryModule = Dictionary<int,String>();
    SocialRecoveryModule.put(2, "setup");
    SocialRecoveryModule.put(4, "recoverAccess");
    SocialRecoveryModule.put(5, "confirmTransaction");
    SocialRecoveryModule.put(6, "changeMasterCopy");
    Dictionary<int,String> WhitelistModule = Dictionary<int,String>();
    WhitelistModule.put(0, "executeWhitelisted");
    WhitelistModule.put(3, "changeMasterCopy");
    WhitelistModule.put(4, "removeFromWhitelist");
    WhitelistModule.put(6, "setup");
    WhitelistModule.put(7, "addToWhitelist");
    Dictionary<int,String> CreateAndAddModules = Dictionary<int,String>();
    CreateAndAddModules.put(0, "createAndAddModules");
    CreateAndAddModules.put(1, "enableModule");
    Dictionary<int,String> MultiSend = Dictionary<int,String>();
    MultiSend.put(0,"multiSend");
    */

    String contractAddress1 = "0xd322211f9fec0d98f447532f4b4e063b9fad086c";

    /**
     * Call the set function of the greeter contract
     * @param value : the value to be set in the greeter contract
     * @param address : the address of the user (String, format hex)
     * @param privateKey : the private key of the user (String, format hex, without 0x at the beginning)
     * @return the transaction hash of the transaction used to access the smart contract
     * @throws Exception : for various reasons
     */
    @SimpleFunction(
            description = "setter for greeter smart contract")
    public String set(String value, String address, String privateKey) throws Exception {
        initializeWeb3();

        Credentials credentials = Credentials.create(privateKey);
        assert (credentials.getAddress() == address);

        Uint256 new_value = new Uint256( (long) Integer.parseInt(value));
        List<Type> input = Arrays.<Type>asList( new_value );
        List<TypeReference<?>> output = Arrays.<TypeReference<?>>asList();
        BigInteger gasDefaultValues = BigInteger.valueOf(0);

        return accessNonViewFunction(credentials, contractAddress1, "set", input, output, gasDefaultValues, gasDefaultValues);
    }


    @SimpleFunction(
            description = "getter for greeter smart contract")
    /**
     * Getter for the value of the greeter contract.
     * @return a String of the value, encoded in hex format, of 256 characters.
     * @throws Exception : for various reasons.
     */
    public String get() throws Exception {
        initializeWeb3();
        String address = "0x210053ed365203a6a8f3983f7823b4326fd1f9d7";

        List<Type> input = Arrays.<Type>asList();
        List<TypeReference<?>> output = Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {});

        return accessViewFunction(address, contractAddress1, "get", input, output);
    }

    /**
     * Fonction enabling the user to access any view function of a smart contract, given :
     * @param address : the address of the user (String, format hex)
     * @param contractAddress : the address of the Smart Contract (String, format hex)
     * @param functionName : the string of the method name (ex : "get" for the greeter)
     * @param input : the list of the input of the method
     * @param output : the list of the output of the method
     * @return the list the method returns
     * @throws Exception : for various reasons.
     */
    private String accessViewFunction(String address, String contractAddress,
                                      String functionName, List<Type> input, List<TypeReference<?>> output )
            throws Exception {
        initializeWeb3();

        Function function = new Function(
                functionName,
                input,
                output);
        String encodedFunction = FunctionEncoder.encode(function);

        org.web3j.protocol.core.methods.response.EthCall response = web3.ethCall(
                org.web3j.protocol.core.methods.request.Transaction.createEthCallTransaction(
                        address,
                        contractAddress,
                        encodedFunction),
                DefaultBlockParameterName.LATEST)
                .sendAsync().get();
        return response.getValue().toString();
    }

    /**
     * Fonction enabling the user to access any Non view function of a smart contract, given :
     * @param credentials : the credentials of the user, can be created with the privateKey, by "Credentials.create(privateKey)"
     * @param contractAddress : the address of the Smart Contract (String, format hex)
     * @param functionName : the string of the method name (ex : "set" for the greeter)
     * @param input : the list of the input of the method
     * @param output : the list of the output of the method
     * @param gasPrice : the gasPrice ; to default to the testnet average price, enter "BigInteger.valueOf(0)"
     * @param gasLimit : the gasLimit ; to default to BigInteger.valueOf(4800000), enter "BigInteger.valueOf(0)"
     * @return the hash of the transaction, a String in hex format
     * @throws Exception : for various reasons
     */
    private String accessNonViewFunction(Credentials credentials, String contractAddress,
                                         String functionName, List<Type> input, List<TypeReference<?>> output,
                                         BigInteger gasPrice, BigInteger gasLimit)
            throws Exception {

        //initialisation
        initializeWeb3();

        if (gasPrice.compareTo(BigInteger.valueOf(0)) == 0 ) {
            gasPrice = web3.ethGasPrice().send().getGasPrice();
        }
        if (gasLimit.compareTo(BigInteger.valueOf(0)) == 0 ) {
            gasLimit = BigInteger.valueOf(4800000);
        }
        EthGetTransactionCount ethGetTransactionCount = web3.ethGetTransactionCount(
                credentials.getAddress(), DefaultBlockParameterName.LATEST).sendAsync().get();
        BigInteger nonce = ethGetTransactionCount.getTransactionCount();

        //bouild and send transaction
        Function function = new Function(
                functionName,
                input,
                output);

        String encodedFunction = FunctionEncoder.encode(function);

        RawTransaction rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                gasLimit,
                contractAddress,
                encodedFunction);

        byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
        String hexValue = Numeric.toHexString(signedMessage);

        EthSendTransaction transactionResponse = web3.ethSendRawTransaction(hexValue)
                .sendAsync().get();

        String functionHash = transactionResponse.getTransactionHash();

        return functionHash;
    }

}
