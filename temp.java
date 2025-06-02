package gov.faa.uastrust.config;

import java.util.HashMap;
import java.util.Map;

public class UasTrustContext {
	
	private static final ThreadLocal<Map<String, String>> CONTEXT = ThreadLocal.withInitial(HashMap::new);
	private static final String USER_NAME = "UserName";
	private static final String USER_ROLE = "UserRole";
	private static final String USER_TYPE = "UserType";
	private static final String USER_IP_ADDRESS = "UserIpAddress";
	private static final String USER_HOST_NAME = "UserHostName";
	
	private static void setAttribute(String attributeName, String attributeValue) {
		CONTEXT.get().put(attributeName, attributeValue);
	}
	
	public static String getUserName() {
		return CONTEXT.get().get(USER_NAME);
	}

	public static void setUserName(String userNameValue) {
		setAttribute(USER_NAME, userNameValue);
	}
	
	public static String getUserRole() {
		return CONTEXT.get().get(USER_NAME);
	}

	public static void setUserRole(String userRoleValue) {
		setAttribute(USER_ROLE, userRoleValue);
	}
	
	public static String getUserType() {
		return CONTEXT.get().get(USER_NAME);
	}

	public static void setUserType(String userTypeValue) {
		setAttribute(USER_TYPE, userTypeValue);
	}

	public static String getUserIpAddress() {
		return CONTEXT.get().get(USER_IP_ADDRESS);
	}

	public static void setUserIpAddress(String userIpAddressValue) {
		setAttribute(USER_IP_ADDRESS, userIpAddressValue);
	}

	public static String getUserHostName() {
		return CONTEXT.get().get(USER_HOST_NAME);
	}

	public static void setUserHostName(String userHostNameValue) {
		setAttribute(USER_HOST_NAME, userHostNameValue);
	}
	

}
