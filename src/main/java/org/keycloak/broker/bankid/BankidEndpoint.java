package org.keycloak.broker.bankid;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import java.awt.image.BufferedImage;
import java.awt.image.DataBufferInt;
import java.io.IOException;
import java.io.OutputStream;
import jakarta.ws.rs.core.StreamingOutput;
import javax.imageio.ImageIO;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.ResponseBuilder;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.CacheControl;

import org.infinispan.Cache;
import org.jboss.logging.Logger;
import org.keycloak.broker.bankid.client.BankidClientException;
import org.keycloak.broker.bankid.client.SimpleBankidClient;
import org.keycloak.broker.bankid.model.AuthResponse;
import org.keycloak.broker.bankid.model.BankidHintCodes;
import org.keycloak.broker.bankid.model.BankidUser;
import org.keycloak.broker.bankid.model.CollectResponse;
import org.keycloak.broker.bankid.model.CompletionData;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProvider.AuthenticationCallback;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.sessions.AuthenticationSessionModel;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

public class BankidEndpoint {

	private BankidIdentityProviderConfig config;
	private AuthenticationCallback callback;
	private BankidIdentityProvider provider;
	private SimpleBankidClient bankidClient;
	private static final Logger logger = Logger.getLogger(BankidEndpoint.class);

	// The maximum number of minutes to store bankid session info in the token cache
	// Setting this to 5 since BankID will timeout after 3 minutes
	private static long MAX_CACHE_LIFESPAN = 5;

	private Cache<Object, Object> actionTokenCache;

	private static String qrCodePrefix = "bankid.";

	private static final int QR_CODE_SIZE = 246;
	private static final int QR_COLOR_ON = 0xFF000000;
	private static final int QR_COLOR_OFF = 0xFFFFFFFF;

	public BankidEndpoint(BankidIdentityProvider provider, BankidIdentityProviderConfig config,
			AuthenticationCallback callback) {
		this.config = config;
		this.callback = callback;
		this.provider = provider;
		this.bankidClient = provider.getBankidClient();
		InfinispanConnectionProvider infinispanConnectionProvider = provider.getSession()
				.getProvider(InfinispanConnectionProvider.class);
		this.actionTokenCache = infinispanConnectionProvider.getCache(InfinispanConnectionProvider.ACTION_TOKEN_CACHE);
	}

	@GET
	@Path("/start")
	public Response start(@QueryParam("state") String state) {

		if (state == null) {
			return callback.error(config, "bankid.hints." + BankidHintCodes.internal.messageShortName);
		}

		if (config.isRequiredNin()) {
			LoginFormsProvider loginFormsProvider = provider.getSession().getProvider(LoginFormsProvider.class);
			return loginFormsProvider
					.setAttribute("state", state)
					.createForm("start-bankid.ftl");
		} else {
			// Go direct to login if we do not require non.
			return doLogin(null, state);
		}
	}

	@POST
	@Path("/login")
	public Response loginPost(@FormParam("nin") String nin, @FormParam("state") String state) {
		return doLogin(nin, state);
	}

	@GET
	@Path("/login")
	public Response loginGet(@QueryParam("state") String state) {
		return doLogin(null, state);
	}

	private Response doLogin(String nin, String state) {
		LoginFormsProvider loginFormsProvider = provider.getSession().getProvider(LoginFormsProvider.class);

		try {
			AuthResponse authResponse;
			authResponse = bankidClient.sendAuth(nin, provider.getSession().getContext().getConnection().getRemoteAddr());

			UUID bankidRef = UUID.randomUUID();
			this.actionTokenCache.put(bankidRef.toString(), authResponse, MAX_CACHE_LIFESPAN, TimeUnit.MINUTES);
			return loginFormsProvider
					.setAttribute("bankidref", bankidRef.toString())
					.setAttribute("state", state)
					.setAttribute("autoStartToken", authResponse.getAutoStartToken())
					.setAttribute("showqr", config.isShowQRCode()).setAttribute("ninRequired", config.isRequiredNin())
					.createForm("login-bankid.ftl");
		} catch (BankidClientException e) {
			return loginFormsProvider.setError("bankid.hints." + e.getHintCode().messageShortName)
					.createErrorPage(Status.INTERNAL_SERVER_ERROR);
		}
	}

	@GET
	@Path("/collect")
	public Response collect(@QueryParam("bankidref") String bankidRef) {
		if (!this.actionTokenCache.containsKey(bankidRef) ||
				!(this.actionTokenCache.get(bankidRef) instanceof AuthResponse)) {
			LoginFormsProvider loginFormsProvider = provider.getSession().getProvider(LoginFormsProvider.class);
			return loginFormsProvider.setError("bankid.error.internal").createErrorPage(Status.INTERNAL_SERVER_ERROR);
		}

		if (this.actionTokenCache.containsKey(bankidRef)) {

			String orderref = ((AuthResponse) this.actionTokenCache.get(bankidRef)).getOrderRef();
			try {
				CollectResponse responseData = bankidClient.sendCollect(orderref);
				// Check responseData.getStatus()
				if ("failed".equalsIgnoreCase(responseData.getStatus())) {
					return Response.status(Status.INTERNAL_SERVER_ERROR)
							.entity(String.format("{ \"status\": \"%s\", \"hintCode\": \"%s\" }",
									responseData.getStatus(), responseData.getHintCode()))
							.type(MediaType.APPLICATION_JSON_TYPE).build();
				} else {
					if ("complete".equalsIgnoreCase(responseData.getStatus())) {
						this.actionTokenCache.put(bankidRef + "-completion", responseData.getCompletionData());
					}
					return Response.ok(String.format("{ \"status\": \"%s\", \"hintCode\": \"%s\" }",
							responseData.getStatus(), responseData.getHintCode()), MediaType.APPLICATION_JSON_TYPE)
							.build();
				}
			} catch (BankidClientException e) {
				return Response
						.status(Status.INTERNAL_SERVER_ERROR).entity(String
								.format("{ \"status\": \"%s\", \"hintCode\": \"%s\" }", "failed", e.getHintCode()))
						.type(MediaType.APPLICATION_JSON_TYPE).build();
			}
		} else {
			return Response.ok(String.format("{ \"status\": \"%s\", \"hintCode\": \"%s\" }", "500", "internal"),
					MediaType.APPLICATION_JSON_TYPE).build();
		}
	}

	@GET
	@Path("/done")
	public Response done(@QueryParam("state") String state, @QueryParam("bankidref") String bankidRef) {
		LoginFormsProvider loginFormsProvider = provider.getSession().getProvider(LoginFormsProvider.class);

		if (!this.actionTokenCache.containsKey(bankidRef + "-completion") ||
				!(this.actionTokenCache.get(bankidRef + "-completion") instanceof CompletionData)) {
			logger.error("Action token cache does not have a CompletionData object.");
			return loginFormsProvider.setError("bankid.error.internal").createErrorPage(Status.INTERNAL_SERVER_ERROR);
		}

		CompletionData completionData = (CompletionData) this.actionTokenCache.get(bankidRef + "-completion");
		BankidUser user = completionData.getUser();
		// Make sure to remove the authresponse attribute from the session
		try {
			AuthenticationSessionModel authSession = this.callback.getAndVerifyAuthenticationSession(state);
			provider.getSession().getContext().setAuthenticationSession(authSession);
			BrokeredIdentityContext identity = new BrokeredIdentityContext(
					getConfig().getAlias().concat("." + getUsername(user)), getConfig());

			identity.setIdp(provider);
			identity.setUsername(getUsername(user));
			identity.setFirstName(user.getGivenName());
			identity.setLastName(user.getSurname());

			// Set user session notes
			authSession.setUserSessionNote(getConfig().getAlias().concat(".pnr"), getUsername(user));
			authSession.setUserSessionNote(getConfig().getAlias().concat(".issuedate"),
					completionData.getBankIdIssueDate());
			authSession.setUserSessionNote(getConfig().getAlias().concat(".device.ipaddress"),
					completionData.getDevice().getIpAddress());
			authSession.setUserSessionNote(getConfig().getAlias().concat(".ocspresponse"),
					completionData.getOcspResponse());
			identity.setAuthenticationSession(authSession);

			return callback.authenticated(identity);
		} catch (Exception e) {
			throw new RuntimeException("Failed to decode user information.", e);
		}
	}

	private String getUsername(BankidUser user) throws NoSuchAlgorithmException {
		if (this.config.isSaveNinHashed()) {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(user.getPersonalNumber().getBytes());
			return Base64.getEncoder().encodeToString(md.digest());
		} else {
			return user.getPersonalNumber();
		}
	}

	@GET
	@Path("/cancel")
	public Response cancel(@QueryParam("bankidref") String bankidRef) {
		LoginFormsProvider loginFormsProvider = provider.getSession().getProvider(LoginFormsProvider.class);

		if (!this.actionTokenCache.containsKey(bankidRef) ||
				!(this.actionTokenCache.get(bankidRef) instanceof AuthResponse)) {
			return loginFormsProvider.setError("bankid.error.internal").createErrorPage(Status.INTERNAL_SERVER_ERROR);
		}

		if (!this.actionTokenCache.containsKey(bankidRef) ||
				!(this.actionTokenCache.get(bankidRef) instanceof AuthResponse)) {
			return loginFormsProvider.setError("bankid.error.internal").createErrorPage(Status.INTERNAL_SERVER_ERROR);
		}

		AuthResponse authResponse = (AuthResponse) this.actionTokenCache.get(bankidRef);
		if (authResponse != null) {
			String orderRef = authResponse.getOrderRef();
			bankidClient.sendCancel(orderRef);
		}
		return loginFormsProvider.setError("bankid.hints." + BankidHintCodes.cancelled.messageShortName)
				.createErrorPage(Status.OK);
	}

	@GET
	@Path("/error")
	public Response error(@QueryParam("code") String hintCode) {

		BankidHintCodes hint;
		// Sanitize input from the web
		try {
			hint = BankidHintCodes.valueOf(hintCode);
		} catch (IllegalArgumentException e) {
			hint = BankidHintCodes.unkown;
		}
		LoginFormsProvider loginFormsProvider = provider.getSession().getProvider(LoginFormsProvider.class);
		return loginFormsProvider.setError("bankid.hints." + hint.messageShortName)
				.createErrorPage(Status.INTERNAL_SERVER_ERROR);
	}

	@GET
	@Path("/qrcode")
	public Response qrcode(@QueryParam("bankidref") String bankidRef) {
		if (this.actionTokenCache.containsKey(bankidRef)) {
			LoginFormsProvider loginFormsProvider = provider.getSession().getProvider(LoginFormsProvider.class);
			if (!this.actionTokenCache.containsKey(bankidRef) &&
					!(this.actionTokenCache.get(bankidRef) instanceof AuthResponse)) {
				return loginFormsProvider.setError("bankid.error.internal")
						.createErrorPage(Status.INTERNAL_SERVER_ERROR);
			}

			AuthResponse authResponse = (AuthResponse) this.actionTokenCache.get(bankidRef);
			long elapsedTime = (System.currentTimeMillis() / 1000) - authResponse.getAuthTimestamp();

			String qrAuthCode;
			try {
				qrAuthCode = generateQrAuthCode(authResponse.getQrStartSecret(), Long.toString(elapsedTime));
			} catch (Exception e) {
				logger.error("Failed to generate qrAuthCode");
				throw new RuntimeException(e);
			}

			String qrCode = qrCodePrefix + authResponse.getQrStartToken() + "." + elapsedTime + "." + qrAuthCode;

			try {
				QRCodeWriter writer = new QRCodeWriter();

				final BitMatrix bitMatrix = writer.encode(qrCode, BarcodeFormat.QR_CODE, QR_CODE_SIZE, QR_CODE_SIZE);

				CacheControl cc = new CacheControl();
				cc.setNoStore(true);

				StreamingOutput stream = output -> writeQrCodePng(bitMatrix, output);
				ResponseBuilder builder = Response.ok(stream, "image/png");

				builder.cacheControl(cc);
				return builder.build();
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
		return Response.serverError().build();
	}

	private void writeQrCodePng(BitMatrix bitMatrix, OutputStream output) throws IOException {
		BufferedImage image = new BufferedImage(bitMatrix.getWidth(), bitMatrix.getHeight(), BufferedImage.TYPE_INT_RGB);
		int[] pixels = ((DataBufferInt) image.getRaster().getDataBuffer()).getData();
		int width = bitMatrix.getWidth();
		int height = bitMatrix.getHeight();
		int index = 0;

		// Fill the image backing array directly to avoid extra pixel buffers.
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
					pixels[index++] = bitMatrix.get(x, y) ? QR_COLOR_ON : QR_COLOR_OFF;
			}
		}

		if (!ImageIO.write(image, "png", output)) {
			throw new IOException("Failed to write QR code image");
		}
	}

	public BankidIdentityProviderConfig getConfig() {
		return config;
	}

	private String generateQrAuthCode(String qrStartSecret, String time)
			throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(qrStartSecret.getBytes("ascii"), "HmacSHA256"));

		return String.format("%064x", new BigInteger(1, mac.doFinal(new String(time).getBytes())));
	}
}
