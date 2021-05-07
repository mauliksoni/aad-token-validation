import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;
import com.auth0.jwk.*;
import com.auth0.jwt.*;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;

  public class ValidateAADToken
  {
  
    public string ValidateToken(){
        System.out.println("AAD Token Validation");
        
        // Validate Azure AD Token
        String token = "eyJ0.....";
        DecodedJWT jwt = JWT.decode(token);
        System.out.println(jwt.getKeyId());

        JwkProvider provider = null;
        Jwk jwk = null;
        Algorithm algorithm = null;

        try {
        
            provider = new UrlJwkProvider(new URL("https://login.microsoftonline.com/common/discovery/keys"));
            jwk = provider.get(jwt.getKeyId());
            algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            algorithm.verify(jwt);// if the token signature is invalid, the method will throw
                                  // SignatureVerificationException
            try {
                JWTVerifier verifier = JWT.require(algorithm).withAudience("api://d92655f6-2a63-458b-9fe2-187e176397b4")
                        .withClaim("roles", "DaemonAppRole").build(); // Reusable verifier instance
                DecodedJWT jwt2 = verifier.verify(token);
            } catch (TokenExpiredException e) {
                System.out.println("Token is expired");
            } catch (InvalidClaimException e) {
                System.out.println("Invalid Claim for Audience");
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (JwkException e) {
            e.printStackTrace();
        } catch (SignatureVerificationException e) {
            System.out.println(e.getMessage());
        }
    }
  }
