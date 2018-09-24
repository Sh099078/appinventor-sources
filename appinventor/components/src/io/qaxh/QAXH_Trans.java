package io.qaxh.trans;

import com.google.appinventor.components.runtime.Component;
import com.google.appinventor.components.runtime.AndroidNonvisibleComponent;
import com.google.appinventor.components.runtime.ComponentContainer;

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

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.jcajce.provider.digest.Keccak;

import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.Function;

import io.qaxh.eth.QAXH_Eth;

@DesignerComponent(version = YaVersion.QAXH_TRANS_COMPONENT_VERSION,
        description = "This component implements country and city code translation.",
        category = ComponentCategory.EXTENSION,
        nonVisible = true,
        iconName = "aiwebres/eth.png")
@SimpleObject(external=true)

public class QAXH_Trans extends AndroidNonvisibleComponent implements Component {

    /**
     * Creates a QAXH_Trans component.
     * <p>
     * This function isn't visible from AppInventor.
     *
     * @param container container, component will be placed in
     */
    public QAXH_Trans(ComponentContainer container) {
        super(container.$form());
    }

    /*
    String contractAddress = "0xd322211f9fec0d98f447532f4b4e063b9fad086c";
    public String set(int number) {
        QAXH_Eth.initializeWeb3();

        Function function = new Function<void>(
                "set",  // function we're calling
                Arrays.asList(new Uint256((long) number)),  // Parameters to pass as Solidity Types
                Arrays.asList(new TypeReference<Uint256>() {}));
        String encodedFunction = FunctionEncoder.encode(function);

        BigInteger gasLimit = BigInteger.valueOf(4800000);
        BigInteger gasPrice = web3.ethGasPrice().send().getGasPrice();
        gasPrice = gasPrice.multiply(BigInteger.valueOf(2));
        Transaction transaction = createFunctionCallTransaction(
               "0x210053ed365203a6a8f3983f7823b4326fd1f9d7" ,
                gasPrice,
                gasLimit,
                contractAddress,
                0, //non payable
                encodedFunction);
        EthSendTransaction transactionResponse =
                web3j.ethSendTransaction(transaction).sendAsync().get();
        String transactionHash = transactionResponse.getTransactionHash();
        return transactionHash;
    }

    public Uint256 get() {
        QAXH_Eth.initializeWeb3();

        Function function = new Function<Uint256>(
                "get",
                Arrays.asList(),  // Solidity Types in smart contract functions
                Arrays.asList());
        String encodedFunction = FunctionEncoder.encode(function);

        EthCall response = web3j.ethCall(
                Transaction.createEthCallTransaction("0x210053ed365203a6a8f3983f7823b4326fd1f9d7", contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST)
             .sendAsync().get();

        Uint256 number = FunctionReturnDecoder.decode(
                response.getValue(), function.getOutputParameters());
        return number;
    }
    */

}