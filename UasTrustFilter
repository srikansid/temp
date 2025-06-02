package gov.faa.uastrust.auth;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class UasTrustFilter extends GenericFilterBean {
	
	
	static final List<String> NO_AUTH_PATHS = new ArrayList<>();
	
	static final List<String> EXTERNAL_REG_AUTH_PATHS = new ArrayList<>();
	
	static final List<String> EXTERNAL_AUTH_PATHS = new ArrayList<>();
	
	static {
		//No Authentication paths
		NO_AUTH_PATHS.add("/auth/extconfig");
		NO_AUTH_PATHS.add("/auth/login/callback");
		NO_AUTH_PATHS.add("/auth/logout");
		NO_AUTH_PATHS.add("/auth/login");
		NO_AUTH_PATHS.add("/api/v1/health_check/probe");
		
		//Valid token but user not needed in UASTrust DB - this is to handle registration
		EXTERNAL_REG_AUTH_PATHS.add("/api/v1/searchUser");
		EXTERNAL_REG_AUTH_PATHS.add("/api/v1/searchTestAuthority");
		EXTERNAL_REG_AUTH_PATHS.add("/api/v1/registerUser");
		
		//Valid token and user must be there in UASTrust DB
		EXTERNAL_AUTH_PATHS.add("/api/v1/testAuthorities/[A-Z]{4}/tokens");
		EXTERNAL_AUTH_PATHS.add("/api/v1/extLoginSuccess");
		
		//All other internal paths has to go thorough internal jwt validation
		
	}
	
	@Autowired
	OktaJwtValidator oktaJwtValidator;
	
	@Autowired
	CustomJwtCreatorAndValidator customJwtCreatorAndValidator;
	

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		
		if(!request.getRequestURI().contains("health_check")) {
			log.info("Client -- "+request.getHeader("client")+ ",  Path -- "+request.getRequestURI());
		}

		
		if(isNoAuthPath(request.getRequestURI())) {
			
			chain.doFilter(request, response);
			
		} else if(request.getHeader("client") != null && request.getHeader("client").equals("external")) {
			
			handleExternalAppSecurity(request, response,chain);
			
		} else if(request.getHeader("client") != null && request.getHeader("client").equals("internal")) {
			
			handleInternalAppSecurity(request, response, chain );
			
		}  
		
	}
	
	private void handleExternalAppSecurity(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
		
		try {
			
			String token = extractTokenFromRequest(request);
			
			if(EXTERNAL_REG_AUTH_PATHS.contains(request.getRequestURI()) && oktaJwtValidator.validate(token, false)) {

				chain.doFilter(request, response);
				
			} else if(checkExternalAuthPath(request.getRequestURI()) && oktaJwtValidator.validate(token, true)) {

				chain.doFilter(request, response);
					
			} else {
				log.error("Not a valid path === ");	
				response.sendError(HttpServletResponse.SC_NOT_ACCEPTABLE, "Not a valid external path === ");
			}
			
		} catch (Exception e) {
			log.error("JWT validation error === ");		
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token validation failed == ");
		}
		
	}
	
	private void handleInternalAppSecurity(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
		String token = extractTokenFromRequest(request);
		
		try {
			
			if(customJwtCreatorAndValidator.validateJWTToken(token)){
				chain.doFilter(request, response);
			} else {
				clearTokenAndSendError(response);
			}
		} catch (Exception e) {
			clearTokenAndSendError(response);
		}
		
	}
	
	private boolean isNoAuthPath(String url) {
		
		return NO_AUTH_PATHS.contains(url);
		
	}
	
	private void clearTokenAndSendError(HttpServletResponse response) {
		try {
			log.error("Token validation failed == ");	
    		Cookie ck = new Cookie("jwt", null);
    		ck.setPath("/");
    		response.addCookie(ck);
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token validation failed == ");
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	
	private String extractTokenFromRequest(HttpServletRequest request) {
		String token = request.getHeader("Authorization");
		if(StringUtils.isNotBlank(token) && token.contains("Bearer")) {
			token = token.substring(7);
		} 
		
		return token;
	}
	
	private boolean checkExternalAuthPath(String path) {
		
		for (int i = 0; i < EXTERNAL_AUTH_PATHS.size(); i++) {
			boolean b = Pattern.compile(EXTERNAL_AUTH_PATHS.get(i)).matcher(path).matches();
			if(b) {
				return true;
			}
		}
		
		return false;
		
	}

}
