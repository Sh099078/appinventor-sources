// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2009-2011 Google, All Rights reserved
// Copyright 2011-2012 MIT, All rights reserved
// Released under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

package io.qaxh.sc;

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

@DesignerComponent(version = YaVersion.QAXH_SC_COMPONENT_VERSION,
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
public class QAXH_SC extends AndroidNonvisibleComponent implements Component {

	private static final String LOG_TAG = "QaxhEthComponent";

	Web3j web3;

	/**
	 * Creates a QAXH_SC component.
	 * <p>
	 * This function isn't visible from AppInventor.
	 *
	 * @param container container, component will be placed in
	 */
	public QAXH_SC(ComponentContainer container) {
		super(container.$form());
		//      initializeWeb3();
		//Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
	}

	/**
	 * Build a Web3j object to access to the blockchain, if one wasn't created before.
	 *
	 * This function isn't visible from AppInventor.
	 */
	//and i know, i just copied the code from qaxh_eth, but it makes both components independents and that's nice
	public void initializeWeb3() {
		if (web3 == null) {
			web3=Web3jFactory.build(new HttpService("https://rinkeby.infura.io/MCLIpiMOeM176U6zBTT5"));
		}
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
	 *
	 * This function isn't visible from AppInventor.
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
	 *
	 * This function isn't visible from AppInventor.
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

	//////////////////////// Functions is UtilsQaxhModule //////////////////////////////////////////////
	/* NOT INCLUDED :
			- setup() : shouldn't revert everytime after creation,
			- filter* : are not functions,
			- replaceOwner : only callable by qaxh, so no use for the app,
			- others : only for development.
	*/

	//////////////////////// Functions is BasicQaxhModule //////////////////////////////////////////////
	/* NOT INCLUDED :
			- handle() : only callable by the safe itself,
			- handleDeposit() : internal,
	*/

	/**
	 * Call the sendFromSafe function of the BasicQaxhModule contract.
	 * Used by the owner of the safe to withdraw money.
	 *
	 * @param safe : the address of the safe to call
	 * @param privateKey : the private key of the sender
	 * @param to : the address to send money to
	 * @param amount : how much to send
	 * @param token : the address of the token to send. O for plain Ether.
	 * @return the transaction hash of the transaction used to access the smart contract
	 * @throws Exception : for various reasons
	 */
	/*
	@SimpleFunction(
			description = "sendFromSafe for BasicQaxhModule : used to withdraw funds, can only be called by the owner of the safe.")
	public String sendFromSafe(String safe, String privateKey, String to, int amount, String token) throws Exception {
		initializeWeb3();

		Credentials credentials = Credentials.create(privateKey);

		Uint256 new_value = new Uint256( (long) Integer.parseInt(amount));
		List<Type> input = Arrays.<Type>asList(to , new_value, token);
		List<TypeReference<?>> output = Arrays.<TypeReference<?>>asList();
		BigInteger gasDefaultValues = BigInteger.valueOf(0);

		return accessNonViewFunction(credentials, safe, "sendFromSafe", input, output, gasDefaultValues, gasDefaultValues);
	}
	*/

	//////////////////////// Functions is AllowanceQaxhModule //////////////////////////////////////////////
	/* NOT INCLUDED :
			- isUnderAllowance(), sendByAllowance() : internal.
	*/

	/**
	 * Call the transferFrom function of the AllowanceQaxhModule contract.
	 * Used by any user to withdraw funds from a safe in which he is allowed to.
	 *
	 * @param safe : the address of the safe to call
	 * @param privateKey : the private key of the sender
	 * @param to : the address to send money to
	 * @param amount : how much to send
	 * @param token : the address of the token to send. O for plain Ether.
	 * @return the transaction hash of the transaction used to access the smart contract
	 * @throws Exception : for various reasons
	 */
	/*
	@SimpleFunction(
			description = "transferFrom of AllowanceQaxhModule : used by users with an allowance to withraw funds. ")
	public String transferFrom(String safe, String privateKey, String to, int amount, String token) throws Exception {
		initializeWeb3();

		Credentials credentials = Credentials.create(privateKey);

		Uint256 new_value = new Uint256( (long) Integer.parseInt(amount));
		List<Type> input = Arrays.<Type>asList(to , new_value, token);
		List<TypeReference<?>> output = Arrays.<TypeReference<?>>asList();
		BigInteger gasDefaultValues = BigInteger.valueOf(0);

		return accessNonViewFunction(credentials, safe, "transferFrom", input, output, gasDefaultValues, gasDefaultValues);
	}
	*/

	/**
	 * Call the changeAllowance function of the AllowanceQaxhModule contract.
	 * Used by the owner of the safe give allowance to another user.
	 * This user must be a qaxh safe.
	 *
	 * @param safe : the address of the safe to call
	 * @param privateKey : the private key of the sender
	 * @param user : the user to allow
	 * @param allowance : the amount to allow
	 * @param token : the address of the token to send. O for plain Ether.
	 * @return the transaction hash of the transaction used to access the smart contract
	 * @throws Exception : for various reasons
	 */
	/*
	@SimpleFunction(
			description = "transferFrom of AllowanceQaxhModule : used by users with an allowance to withraw funds. ")
	public String changeAllowance(String safe, String privateKey, String user, int allowance, String token) throws Exception {
		initializeWeb3();

		Credentials credentials = Credentials.create(privateKey);

		Uint256 new_value = new Uint256( (long) Integer.parseInt(amount));
		List<Type> input = Arrays.<Type>asList(to , new_value, token);
		List<TypeReference<?>> output = Arrays.<TypeReference<?>>asList();
		BigInteger gasDefaultValues = BigInteger.valueOf(0);

		return accessNonViewFunction(credentials, safe, "changeAllowance", input, output, gasDefaultValues, gasDefaultValues);
	}
	*/

	/**
	 * Call the getAllowance function of the AllowanceQaxhModule contract.
	 * Get the allowance of a specific user in a specific token.
	 *
	 * @peram safe : the address of the safe to call
	 * @param address : your address, to send the request from
	 * @param user : the address of the user
	 * @param token : the address of the token. O for plain Ether.
	 * @return a String of the allowance of this user for this token, encoded in hex format, of 256 characters.
	 * @throws Exception : for various reasons.
	 */
	/*
	@SimpleFunction(
			description = "getAllowance of AllowanceQaxhModule : get the amount of allowance of an user in a specific token.")
	public String getAllowance( String safe, String address, String user, String token) throws Exception {
		initializeWeb3();

		List<Type> input = Arrays.<Type>asList(user, token);
		List<TypeReference<?>> output = Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {});

		return accessViewFunction(address, safe, "getAllowance", input, output);
	}
	*/

}