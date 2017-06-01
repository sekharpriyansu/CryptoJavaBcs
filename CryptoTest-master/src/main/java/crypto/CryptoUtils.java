package crypto;

/**
 * Created by James on 1/06/2017.
 */

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.math.BigInteger;
import java.security.*;
import java.util.Random;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAKey;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.util.Random;

public class CryptoUtils
{
    private static KeyPair mCurrentKeyPair = null;
    private static EdDSANamedCurveSpec mEd25519Curve;
    private static String mEncryptedKey;
    private static KeyPairGenerator mKeyPairG = null;

    public KeyPair getCurrentKeyPair()
    {
        return mCurrentKeyPair;
    }

    public static PublicKey getPublicKey()
    {
        GenerateKeyPair();
        if (mCurrentKeyPair != null)
        {
            return mCurrentKeyPair.getPublic();
        }
        else
        {
            return null;
        }
    }

    public String getEncryptedKey()
    {
        return mEncryptedKey;
    }

    public String getPublicKeyString()
    {
        String key = getBase58(mCurrentKeyPair.getPublic());
        return key;
    }

    public static String getPublicKeyStringS()
    {
        String key = getBase58(mCurrentKeyPair.getPublic());
        return key;
    }

    public String getPrivateKeyString()
    {
        byte[] privateKeyBytes = mCurrentKeyPair.getPrivate().getEncoded();
        String privateKey = ToBase58(privateKeyBytes);
        return privateKey;
    }

    public static void GenerateKeyPair()
    {
        if (mCurrentKeyPair != null) return;

        if (mKeyPairG == null)
        {
            mKeyPairG = new KeyPairGenerator();
        }

        if (mCurrentKeyPair == null)
        {
            try
            {
                mCurrentKeyPair = mKeyPairG.generateKeyPair();
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
    }

    /**
     * Gets the transaction bytes sent from the server, signs and then puts a request to send them back
     */
    public static byte[] SignTransaction(byte[] signRequest)
    {
        GenerateKeyPair();
        byte[] signed = null;

        try
        {
            EdDSAEngine signer = new EdDSAEngine();
            signer.initSign(mCurrentKeyPair.getPrivate());
            signer.update(signRequest);
            signed = signer.sign();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return signed;
    }

    public KeyPair generateKeyPairFromSeed(long seed)
    {
        if (mCurrentKeyPair != null)
        {
            return mCurrentKeyPair;
        }


        if(seed == 0)
        {
            Random randomSeed = new Random();
            seed = randomSeed.nextLong();
        }

        return GenerateKPFromBigInt(BigInteger.valueOf(seed));
    }

    public KeyPair GenerateKPFromBigInt(BigInteger b)
    {
        EdDSANamedCurveSpec params = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
        int seedLength = params.getCurve().getField().getb() / 8;
        byte[] seedArray = new byte[seedLength];
        byte[] bits = b.toByteArray();
        System.arraycopy(bits, 0, seedArray, 0, bits.length);
        EdDSAPrivateKeySpec priv = new EdDSAPrivateKeySpec(seedArray, params);
        EdDSAPublicKeySpec pub = new EdDSAPublicKeySpec(priv.getA(), params);
        mCurrentKeyPair = new KeyPair(new EdDSAPublicKey(pub), new EdDSAPrivateKey(priv));
        return mCurrentKeyPair;
    }
    public static boolean verify(byte [] message, byte [] publicKey, byte[] signature) throws Exception
    {
        EdDSANamedCurveSpec params = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(params.getHashAlgorithm()));
        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(publicKey, params);
        PublicKey vKey = new EdDSAPublicKey(pubKey);
        try {
            sgr.initVerify(vKey);
            sgr.update(message);
            sgr.verify(signature);
        }catch (SignatureException se)
        {
            return false;
        }
        return true;
    }

    //Utility functions
    private static String getBase58(PublicKey key)
    {
        EdDSAPublicKey edKey = (EdDSAPublicKey) key;
        String b58 = Base58.encode(edKey.getAbyte());
        return b58;
    }

    private static String ToBase58(byte[] info)
    {
        return Base58.encode(info);
    }

    private String getBase58Pt2(PublicKey key)
    {
        String b58 = Base58.encode(key.getEncoded());
        return b58;
    }
}
