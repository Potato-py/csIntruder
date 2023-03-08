import java.io.File;
import java.util.Base64;
import common.CommonUtils;
import java.security.KeyPair;

class DumpKeys
{   
    public static void main(String[] args)
    {
        try {
            File file = new File(".cobaltstrike.beacon_keys");
            if (file.exists()) {
                KeyPair keyPair = (KeyPair)CommonUtils.readObject(file, null);
                System.out.printf("Private Key: %s\n\n", new String(Base64.getEncoder().encode(keyPair.getPrivate().getEncoded())));
                System.out.printf("Public Key: %s\n\n", new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
            }
            else {
                System.out.println("Could not find .cobaltstrike.beacon_keys file");
            }
        }
        catch (Exception exception) {
           System.out.println("Could not read asymmetric keys");
        }
    }
}
