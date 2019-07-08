package tbuk;
import java.text.ParseException;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;

public class EdDSA_Sample_For_Cem_try {
	public static void main(String[] args) throws JOSEException, ParseException {
		// Bu bizim kullanmakta anlastigimiz key 
		String private_jsonObject="{\"kty\":\"OKP\",\"d\":\"jXU4ZZUnqnNmDAwtm_0tpse80erzQfADBZIpgXczI70\",\"crv\":\"Ed25519\",\"x\":\"GGo29vo73dE296fO8-PT3ywf-clI3KBjS0_3DoKvYm4\"}";
        OctetKeyPair jwk=OctetKeyPair.parse(private_jsonObject);
        OctetKeyPair publicJWK = jwk.toPublicJWK();
		
		// Create the EdDSA signer - EDDSA ile sign etmek icin, yoksa baska signer da olur
		JWSSigner signer = new Ed25519Signer(jwk);

		// Creates the JWS object with payload
		JWSObject jwsObject = new JWSObject(
		    new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(jwk.getKeyID()).build(),
		    new Payload("Buraya ister json istedigini koy.. bize geri geldiginde isine yarayacak seyleri koy"));

		// JWS tokenimizi  EdDSA signature ile sign edelim
		jwsObject.sign(signer);

		// Serialize the JWS - jws'i string hale getirelim ki bunu donecegiz adamlara
		String sJWS = jwsObject.serialize();


		// Verifier - bu verify yapmak icin ( Karsi taraf yapacak, biz de ilk geldiginde)
		JWSVerifier verifier = new Ed25519Verifier(publicJWK);

		 // Verify the EdDSA signature : jwsObject.verify methodu true ya da false doner
		System.out.println(jwsObject.verify(verifier));
		System.out.println(jwsObject.getPayload().toString());
		
		System.out.println("Bearer "+sJWS.toString());

	}
	
	private static void generateNew() {
		// Generate a key pair with Ed25519 curve
				// OctetKeyPairGenerator jwkGen = new OctetKeyPairGenerator(Curve.Ed25519);// new OctetKeyPairGenerator(Curve.Ed25519).keyID("123").generate();
				 // jwkGen.keyID("123");
				// OctetKeyPair jwk=jwkGen.generate();
				// OctetKeyPair publicJWK = jwk.toPublicJWK();
		        // d: private , x: public 
				
		
	}

}
