package crypto;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.Option.Builder;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.ParseException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.interfaces.ECKey;
import java.util.stream.Collectors;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

/**
 * Created by James on 1/06/2017.
 */

// goal:
    // Create a command line app that does the following:
    // 1. accept a phrase which is converted into a public key and output it in base58 thus:
    // cryptotest -showkey -p "my dog smells like armpits"
    //
    // this will produce a signature and public key, say o4r5tte55vfFFgh ...
    //
    // 2. sign a document using the keypair:
    //
    // cryptotest -sign -p "my dog smells like armpits" -s importantDoc.pdf
    //
    // which will produce the signature, which can also be in base58, say 00ttcvujRTRTG4 ...
    //
    // 3. check the signature given a public key, thus:
    //
    // cryptotest -check -pk "o4r5tte55vfFFgh ..." -s importantDoc.pdf -sig "00ttcvujRTRTG4 ..."
    //
    // the output from the test should be true or false, depending on if the signature matches the key

public class MainApp {
    public static BigInteger stringToBigInt(String key) throws Exception
    {
        MessageDigest md=MessageDigest.getInstance("SHA-256");
        md.update(key.getBytes("UTF-8"));
        return  new BigInteger(md.digest());
    }
    public static void main(String[] args) throws Exception {
        CommandLine commandLine;
        Option optShowKey = Option.builder("showkey")
                .required(false)
                .desc("This is to show key")
                .longOpt("showkey")
                .build();
        Option optSign = Option.builder("sign")
                .required(false)
                .desc("This is to sign a doc")
                .longOpt("sign")
                .build();
        Option optCheck = Option.builder("check")
                .required(false)
                .desc("This is to check signature")
                .longOpt("check")
                .build();

        Option optPrivateKey = Option.builder("p")
                .required(false)
                .desc("Private Key Option")
                .longOpt("p")
                .numberOfArgs(1)
                .build();

        Option optSingingFile = Option.builder("s")
                .required(false)
                .desc("Signing File")
                .longOpt("s")
                .numberOfArgs(1)
                .build();

        Option optPublicKey = Option.builder("pk")
                .required(false)
                .desc("Public Key Option")
                .longOpt("pk")
                .numberOfArgs(1)
                .build();

        Option optSignature = Option.builder("sig")
                .required(false)
                .desc("signature of doc")
                .longOpt("sig")
                .numberOfArgs(1)
                .build();

//        String[] testArgs = {"-showkey", "-p", "my dog smells like armpits"};
//        String[] testArgs = {"-sign", "-p", "my dog smells like armpits", "-s", "importantDoc.pdf"};

//        String[] testArgs = { "-check", "-pk", "4Bxmp4BQHiAgm9553LC9QaCCEqfwdMcLwL297Hpm3b1E", "-s",
//                "importantDoc.pdf", "-sig",
//                "m8ooQH7w5zfwBu9mPqoGxPrXuP4v3oAiDKU2toFnjgZqq4H6DZ3xkGXCNfrNsW4iJpQL8B7u3jfqyFzKYoBaYp"};
        Options options = new Options();
        options.addOption(optShowKey);
        options.addOption(optPublicKey);
        options.addOption(optPrivateKey);
        options.addOption(optSingingFile);
        options.addOption(optSign);
        options.addOption(optCheck);
        options.addOption(optSignature);

        CommandLineParser parser = new DefaultParser();
        try {
            commandLine = parser.parse(options, args);
            CryptoUtils crypto=new CryptoUtils();
            Base58 base58=new Base58();

            if (commandLine.hasOption("showkey")) {
                BigInteger bi;
                bi=stringToBigInt(commandLine.getOptionValue("p"));
                crypto.GenerateKPFromBigInt(bi);
                System.out.print("Public Key base58: ");
                System.out.print(crypto.getPublicKeyString());
            }
            if (commandLine.hasOption("sign")) {
                BigInteger bi;
                bi=stringToBigInt(commandLine.getOptionValue("p"));
                crypto.GenerateKPFromBigInt(bi);
                byte[] s = Files.readAllBytes(Paths.get(commandLine.getOptionValue('s')));
                System.out.print("Signature of Document: ");
                System.out.print(base58.encode(crypto.SignTransaction(s)));
            }
            if (commandLine.hasOption("check")) {
                byte[] s = Files.readAllBytes(Paths.get(commandLine.getOptionValue('s')));
                boolean b=crypto.verify(s,base58.decode(commandLine.getOptionValue("pk")),base58.decode(commandLine.getOptionValue("sig")));
                System.out.print(b);
            }
        } catch (ParseException exception) {
            System.out.print("Parse error: ");
            System.out.println(exception.getMessage());
        }
    }
}
