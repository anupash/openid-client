import java.util.*;

public class Main {

	public static void main(String args[]) {
		VerifySignature verify = new VerifySignature(args[0],args[1],args[2]);
		verify.dumpJwtInfo();
        verify.validateToken();
	}
}