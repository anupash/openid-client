import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class VerifySignature
{
    // Sample id_token that needs validation. This is probably the only field you need to change to test your id_token.
    // If it doesn't work, try making sure the MODULUS and EXPONENT constants are what you're using, as detailed below.
    public  String id_token;
    public  String[] id_token_parts;

    // Constants that come from the keys your token was signed with.
    // Correct values can be found from using the "kid" value and looking up the "n (MODULUS)" and "e (EXPONENT)" fields
    // at the following url: https://login.salesforce.com/id/keys
    // The following 2 values are hard coded to work with the "kid=196" key values.
    public  String MODULUS;
    public  String EXPONENT;

    public  String ID_TOKEN_HEADER;
    public  String ID_TOKEN_PAYLOAD;
    public  byte[] ID_TOKEN_SIGNATURE;

	public VerifySignature(String id_token, String modulus, String exponent) {
		this.id_token = id_token;
		this.MODULUS = modulus;
		this.EXPONENT = exponent;

		System.out.println("id_token = " + id_token);
		System.out.println("modulus = " + modulus);
		System.out.println("exponent = " + exponent);		
		id_token_parts = id_token.split("\\.");
		
		ID_TOKEN_HEADER = base64UrlDecode(id_token_parts[0]);
		ID_TOKEN_PAYLOAD = base64UrlDecode(id_token_parts[1]);
		ID_TOKEN_SIGNATURE = base64UrlDecodeToBytes(id_token_parts[2]);
	}
	
    public  String base64UrlDecode(String input)
    {
        byte[] decodedBytes = base64UrlDecodeToBytes(input);
        String result = new String(decodedBytes, StandardCharsets.UTF_8);
        return result;
    }

    public  byte[] base64UrlDecodeToBytes(String input)
    {
        byte[] decodedBytes = Base64.getUrlDecoder().decode(input);

        return decodedBytes;
    }

    public  void dump(String data)
    {
        System.out.println(data);
    }

    public  void dumpJwtInfo()
    {
        dump(ID_TOKEN_HEADER);
        dump(ID_TOKEN_PAYLOAD);
    }

    public  void validateToken()
    {
        PublicKey publicKey = getPublicKey(MODULUS, EXPONENT);
        byte[] data = (id_token_parts[0] + "." + id_token_parts[1]).getBytes(StandardCharsets.UTF_8);

        try
        {
            boolean isSignatureValid = verifyUsingPublicKey(data, ID_TOKEN_SIGNATURE, publicKey);
            System.out.println("isSignatureValid: " + isSignatureValid);
        }
        catch (GeneralSecurityException e)
        {
            e.printStackTrace();
        }

    }

    public  PublicKey getPublicKey(String MODULUS, String EXPONENT)
    {
        byte[] nb = base64UrlDecodeToBytes(MODULUS);
        byte[] eb = base64UrlDecodeToBytes(EXPONENT);
        BigInteger n = new BigInteger(1, nb);
        BigInteger e = new BigInteger(1, eb);

        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(n, e);
        try
        {
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(rsaPublicKeySpec);

            return publicKey;
        }
        catch (Exception ex)
        {
            throw new RuntimeException("Cant create public key", ex);
        }
    }

    private  boolean verifyUsingPublicKey(byte[] data, byte[] signature, PublicKey pubKey) throws GeneralSecurityException
    {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(data);

        return sig.verify(signature);
    }
}