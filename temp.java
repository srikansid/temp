import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
public class PropertyConfig{
	
	
	@Value("${okta.audience}")
	String oktaAudience;

	@Value("${okta.client.id}")
	String oktaClientId;
	
	@Value("${okta.issuer}")
	String oktaIssuer;
	
	@Value("${okta.logout.uri}")
	String oktaLogoutUri;
	
	@Value("${okta.redirect.uri}")
	String oktaRedirectUri;
	
	@Value("${okta.register.uri}")
	String oktaRegisterUri;

}
