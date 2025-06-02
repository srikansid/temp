package gov.faa.uastrust.auth;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidParameterException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections4.map.HashedMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import gov.faa.uastrust.config.PropertyConfig;
import gov.faa.uastrust.config.UasTrustContext;
import gov.faa.uastrust.entity.UasUsersEntity;
import gov.faa.uastrust.repository.UasUsersRepository;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class OktaJwtValidator {
	
	@Autowired
	PropertyConfig propertyConfig;
	
	@Autowired
	UasUsersRepository usersRepository;
    
    private long lastUserLoadedTime = 0l;
    
    private long lastPublicKeyLoadedTime = 0l;
    
    private Map<String, String> usersOktaMap = new HashedMap<String, String>();
    
    RSAPublicKey rsaPublicKey = null;

    /**
     * Validate a JWT token
     * @param token
     * @return decoded token
     */
    public boolean validate(String encryptedToken, boolean validateUser) {
        try {
        	
        	String token = encryptedToken;
        	
        	token = UASTrustExternalCipher.decrypt(token);
        	
            final DecodedJWT jwt = JWT.decode(token);
            
            verifyAudience(jwt);
            
            verifyIssuer(jwt);
            
            if(validateUser) {
            	validateUser(jwt.getSubject().toLowerCase(), jwt.getClaim("uid").asString());
            }
            
            RSAPublicKey publicKey = loadPublicKey(jwt);

            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(jwt.getIssuer())
                    .build();

            verifier.verify(token);
            
            return true;

        } catch (Exception e) {
            log.error("Failed to validate JWT", e);
            throw new InvalidParameterException("JWT validation failed: " + e.getMessage());
        }

    }
    
    private RSAPublicKey loadPublicKey(DecodedJWT token) throws JwkException, MalformedURLException {
    	
    	Long currentTime = System.currentTimeMillis();
    	
    	if(rsaPublicKey == null || (currentTime - lastPublicKeyLoadedTime) > 1000*60*60*24 ) {
    		
    		log.info("Refreshing public Key cache === ");
    		
            final String url = getProviderCertificateUrl(token);
            JwkProvider provider = new UrlJwkProvider(new URL(url));
            rsaPublicKey = (RSAPublicKey) provider.get(token.getKeyId()).getPublicKey();
            
            lastPublicKeyLoadedTime = currentTime;
    	}
        
        return rsaPublicKey;
    }
    
    private String getProviderCertificateUrl(DecodedJWT token) {
    	return propertyConfig.getOktaIssuer() + "/v1/keys";
    }
    
    private boolean verifyAudience(DecodedJWT jwt) {
    	
    	if(jwt.getAudience()!=null && !jwt.getAudience().isEmpty() && jwt.getAudience().get(0).equals("api://default")) {
    		return true;
    	} else {
    		throw new InvalidParameterException(String.format("Unknown Audience %s", jwt.getAudience()));
    	}

    }
    
    private boolean verifyIssuer(DecodedJWT jwt) {
    	
        if (!propertyConfig.getOktaIssuer().equals(jwt.getIssuer())) {
            throw new InvalidParameterException(String.format("Unknown Issuer %s", jwt.getIssuer()));
        }
        
        return true;
    	
    }
    
    
    private boolean validateUser(String email, String incomingOktaId) {
    	
    	boolean validUser = false;
    	
    	if(usersOktaMap.get(email) != null && usersOktaMap.get(email).equals(incomingOktaId)) {
    		validUser = true;
    	}
    	
    	Long currentTime = System.currentTimeMillis();
    	if(!validUser || (currentTime - lastUserLoadedTime) > 1000*60*10) {
    		
    		log.info("Refreshing users token cache === ");
    		
    		List<UasUsersEntity> usersList = usersRepository.findAll();
    		
    		for (UasUsersEntity uasUsersEntity : usersList) {
    			
    			if(uasUsersEntity.getStatus().equals("AUTHORIZED")) {
    				usersOktaMap.put(uasUsersEntity.getEmail().toLowerCase(), uasUsersEntity.getOktaId());
    			}
				
			}
    		
        	if(usersOktaMap.get(email) != null && usersOktaMap.get(email).equals(incomingOktaId)) {
        		validUser = true;
        	}
        	
        	lastUserLoadedTime = currentTime;
        		
    	}
    	
        if (!validUser) {
            throw new InvalidParameterException(String.format("Unknown user %s", email));
        }
        
        UasTrustContext.setUserName(email);
    	
    	return validUser;
    	
    }
    
}
