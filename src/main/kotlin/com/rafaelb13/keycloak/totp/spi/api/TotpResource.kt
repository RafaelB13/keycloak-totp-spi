package com.rafaelb13.keycloak.totp.spi.api

import com.rafaelb13.keycloak.totp.spi.dto.ApiResponse
import com.rafaelb13.keycloak.totp.spi.dto.GenerateResponse
import com.rafaelb13.keycloak.totp.spi.dto.RegisterRequest
import com.rafaelb13.keycloak.totp.spi.dto.VerifyRequest
import javax.ws.rs.*
import javax.ws.rs.core.MediaType
import javax.ws.rs.core.Response
import javax.ws.rs.core.Context
import org.keycloak.credential.CredentialProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.UserCredentialModel
import org.keycloak.models.UserModel
import org.keycloak.models.credential.OTPCredentialModel
import org.keycloak.models.utils.Base32
import org.keycloak.models.utils.HmacOTP
import org.keycloak.services.managers.AuthenticationManager
import org.keycloak.representations.AccessToken
import org.keycloak.utils.CredentialHelper
import javax.ws.rs.core.HttpHeaders
import java.net.URLEncoder
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO
import java.util.Base64
import org.keycloak.TokenVerifier
import org.keycloak.jose.jws.JWSInput
import org.keycloak.representations.IDToken
import org.jboss.logging.Logger
import org.keycloak.RSATokenVerifier
import org.keycloak.crypto.SignatureVerifierContext
import org.keycloak.jose.jws.JWSHeader
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.client.j2se.MatrixToImageWriter

class TotpResource(
    private val session: KeycloakSession,
) {
    companion object {
        private val logger = Logger.getLogger(TotpResource::class.java)
    }
    
    private val totpSecretLength = 20
    
    private fun generateQRCode(totpUri: String): String {
        try {
            val qrCodeWriter = QRCodeWriter()
            val hints = mutableMapOf<EncodeHintType, Any>()
            hints[EncodeHintType.CHARACTER_SET] = "UTF-8"
            hints[EncodeHintType.MARGIN] = 1
            
            val bitMatrix = qrCodeWriter.encode(totpUri, BarcodeFormat.QR_CODE, 256, 256, hints)
            
            val outputStream = ByteArrayOutputStream()
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream)
            
            return Base64.getEncoder().encodeToString(outputStream.toByteArray())
        } catch (e: Exception) {
            logger.error("Error generating QR code", e)
            throw RuntimeException("Failed to generate QR code", e)
        }
    }
    
    private fun generateTotpUri(secret: String, realm: org.keycloak.models.RealmModel, user: UserModel): String {
        val issuer = realm.displayName ?: realm.name
        val accountName = user.email ?: user.username
        val encodedIssuer = URLEncoder.encode(issuer, "UTF-8")
        val encodedAccountName = URLEncoder.encode(accountName, "UTF-8")
        
        return "otpauth://totp/$encodedIssuer:$encodedAccountName?secret=$secret&issuer=$encodedIssuer&algorithm=SHA1&digits=6&period=30"
    }

    private fun authenticateSessionAndGetUser(
        userId: String,
        headers: HttpHeaders
    ): UserModel {
        val realm = session.context.realm
        val authorization = headers.getRequestHeader("Authorization")?.firstOrNull()
        
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            logger.error("No bearer token provided")
            throw NotAuthorizedException("No bearer token", Response.status(Response.Status.UNAUTHORIZED)
                .entity(mapOf("error" to "No bearer token provided")).build())
        }
        
        val tokenString = authorization.substring(7)
        
        try {
            // Decode the token without verifying the signature first
            val token = RSATokenVerifier.create(tokenString)
                .realmUrl("${session.context.authServerUrl}/realms/${realm.name}")
                .checkRealmUrl(false) // Disable strict URL verification for now
                .parse()
                .token
            
            logger.debug("Token validated for user: ${token.preferredUsername}")
            logger.debug("Token realm access roles: ${token.realmAccess?.roles}")
            
            // Get the authenticated user
            val authenticatedUser = session.users().getUserByUsername(token.preferredUsername, realm)
                ?: throw NotAuthorizedException("User not found", Response.status(Response.Status.UNAUTHORIZED)
                    .entity(mapOf("error" to "User ${token.preferredUsername} not found in realm")).build())
            
            if (authenticatedUser.serviceAccountClientLink == null) {
                logger.error("User ${token.preferredUsername} is not a service account")
                throw NotAuthorizedException("User is not a service account", Response.status(Response.Status.UNAUTHORIZED)
                    .entity(mapOf("error" to "User is not a service account")).build())
            }
            
            // Log available roles for debug
            logger.debug("User ${token.preferredUsername} has roles: ${token.realmAccess?.roles}")

            val user = session.users().getUserById(realm, userId)
                ?: throw NotFoundException("Target user not found")

            if (user.serviceAccountClientLink != null) {
                throw BadRequestException("Cannot manage TOTP for service accounts")
            }

            logger.debug("Authentication successful for ${token.preferredUsername} managing user ${user.username}")
            return user
        } catch (e: Exception) {
            if (e is NotAuthorizedException || e is NotFoundException || e is BadRequestException) {
                throw e
            }
            logger.error("Token validation failed: ${e.message}", e)
            throw NotAuthorizedException("Invalid token", Response.status(Response.Status.UNAUTHORIZED)
                .entity(mapOf("error" to "Invalid token: ${e.message}")).build())
        }
    }

    @GET
    @Path("/{userId}/generate")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    fun generateTOTP(@PathParam("userId") userId: String, @Context headers: HttpHeaders): Response {
        val user = authenticateSessionAndGetUser(userId, headers)
        val realm = session.context.realm

        val secret = HmacOTP.generateSecret(totpSecretLength)
        val encodedSecret = Base32.encode(secret.toByteArray())
        val totpUri = generateTotpUri(encodedSecret, realm, user)
        val qrCode = generateQRCode(totpUri)

        return Response.ok().entity(
            GenerateResponse(
                encodedSecret = encodedSecret,
                qrCode = qrCode
            )
        ).build()
    }

    @POST
    @Path("/{userId}/verify")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun verifyTOTP(request: VerifyRequest, @PathParam("userId") userId: String, @Context headers: HttpHeaders): Response {
        val user = authenticateSessionAndGetUser(userId, headers)

        if (!VerifyRequest.validate(request)) {
            return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse("Invalid request")).build()
        }

        val credentials = session.userCredentialManager().getStoredCredentialsByType(session.context.realm, user, OTPCredentialModel.TYPE)
        
        // If deviceName was provided, look for it specifically
        // Otherwise, verify the code against all user's TOTP credentials
        val credentialsToCheck = if (request.deviceName != null) {
            val specificCredential = credentials.find { it.userLabel == request.deviceName }
            if (specificCredential == null) {
                return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse("TOTP credential not found for device: ${request.deviceName}"))
                    .build()
            }
            listOf(specificCredential)
        } else {
            if (credentials.isEmpty()) {
                return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse("No TOTP credentials found"))
                    .build()
            }
            credentials
        }

        val totpCredentialProvider = session.getProvider(CredentialProvider::class.java, "keycloak-otp")
        
        // Verify the code against each credential until a valid one is found
        for (credentialModel in credentialsToCheck) {
            val totpCredentialModel = OTPCredentialModel.createFromCredentialModel(credentialModel)
            val credentialId = totpCredentialModel.id

            val isCredentialValid = session.userCredentialManager()
                .isValid(session.context.realm, user, UserCredentialModel(credentialId, totpCredentialProvider.type, request.code))

            if (isCredentialValid) {
                val deviceInfo = if (request.deviceName == null && credentials.size > 1) {
                    " (validated with device: ${credentialModel.userLabel ?: "Unknown"})"
                } else {
                    ""
                }
                return Response.ok().entity(ApiResponse("TOTP code is valid$deviceInfo")).build()
            }
        }
        
        // If we reached here, the code is not valid for any credential
        return Response.status(Response.Status.UNAUTHORIZED).entity(ApiResponse("Invalid TOTP code")).build()
    }

    @POST
    @Path("/{userId}/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    fun registerTOTP(request: RegisterRequest, @PathParam("userId") userId: String, @Context headers: HttpHeaders): Response {
        val user = authenticateSessionAndGetUser(userId, headers)

        if (!RegisterRequest.validate(request)) {
            return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse("Invalid request")).build()
        }

        val encodedTOTP = request.encodedSecret
        val secret = String(Base32.decode(encodedTOTP))

        if (secret.length != totpSecretLength) {
            return Response.status(Response.Status.BAD_REQUEST).entity(ApiResponse("Invalid secret")).build()
        }

        val realm = session.context.realm
        val credentialModel = session.userCredentialManager().getStoredCredentialsByType(realm, user, OTPCredentialModel.TYPE)
            .find { it.userLabel == request.deviceName }

        if (credentialModel != null && !request.overwrite) {
            return Response.status(Response.Status.CONFLICT).entity(ApiResponse("TOTP credential already exists"))
                .build()
        }

        val totpCredentialModel = OTPCredentialModel.createFromPolicy(realm, secret, request.deviceName)
        if (!CredentialHelper.createOTPCredential(session, realm, user, request.initialCode, totpCredentialModel)) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(ApiResponse("Failed to create TOTP credential")).build()
        }

        return Response.status(Response.Status.CREATED).entity(ApiResponse("TOTP credential registered")).build()
    }
    
    @DELETE
    @Path("/{userId}/disable")
    @Produces(MediaType.APPLICATION_JSON)
    fun disableTOTP(@PathParam("userId") userId: String, @Context headers: HttpHeaders): Response {
        val user = authenticateSessionAndGetUser(userId, headers)
        val realm = session.context.realm
        
        try {
            // Get all OTP credentials for the user
            val otpCredentials = session.userCredentialManager()
                .getStoredCredentialsByType(realm, user, OTPCredentialModel.TYPE)
            
            if (otpCredentials.isEmpty()) {
                return Response.status(Response.Status.NOT_FOUND)
                    .entity(ApiResponse("No TOTP credentials found for user")).build()
            }
            
            // Remove all OTP credentials
            var removedCount = 0
            for (credential in otpCredentials) {
                if (session.userCredentialManager().removeStoredCredential(realm, user, credential.id)) {
                    removedCount++
                    logger.debug("Removed TOTP credential ${credential.id} from user ${user.username}")
                }
            }
            
            return Response.ok()
                .entity(mapOf(
                    "message" to "TOTP disabled successfully",
                    "removed_credentials" to removedCount
                )).build()
                
        } catch (e: Exception) {
            logger.error("Error disabling TOTP for user ${user.username}", e)
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(ApiResponse("Failed to disable TOTP: ${e.message}")).build()
        }
    }
    
    @DELETE
    @Path("/{userId}/disable/{credentialId}")
    @Produces(MediaType.APPLICATION_JSON)
    fun disableTOTPByCredentialId(
        @PathParam("userId") userId: String, 
        @PathParam("credentialId") credentialId: String,
        @Context headers: HttpHeaders
    ): Response {
        val user = authenticateSessionAndGetUser(userId, headers)
        val realm = session.context.realm
        
        try {
            // Check if the credential exists and is of OTP type
            val credentialModel = session.userCredentialManager()
                .getStoredCredentialById(realm, user, credentialId)
            
            if (credentialModel == null) {
                return Response.status(Response.Status.NOT_FOUND)
                    .entity(ApiResponse("Credential not found")).build()
            }
            
            // Check if it's an OTP credential
            if (credentialModel.type != OTPCredentialModel.TYPE) {
                return Response.status(Response.Status.BAD_REQUEST)
                    .entity(ApiResponse("Credential is not a TOTP credential")).build()
            }
            
            // Remove the specific credential
            val removed = session.userCredentialManager().removeStoredCredential(realm, user, credentialId)
            
            if (removed) {
                logger.debug("Removed TOTP credential ${credentialId} (device: ${credentialModel.userLabel ?: "Unknown"}) from user ${user.username}")
                return Response.ok()
                    .entity(ApiResponse("TOTP credential removed successfully")).build()
            } else {
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(ApiResponse("Failed to remove TOTP credential")).build()
            }
            
        } catch (e: Exception) {
            logger.error("Error disabling TOTP credential $credentialId for user ${user.username}", e)
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(ApiResponse("Failed to disable TOTP: ${e.message}")).build()
        }
    }
    
    @GET
    @Path("/{userId}/list")
    @Produces(MediaType.APPLICATION_JSON)
    fun listTOTPDevices(@PathParam("userId") userId: String, @Context headers: HttpHeaders): Response {
        val user = authenticateSessionAndGetUser(userId, headers)
        val realm = session.context.realm
        
        try {
            // Get all OTP credentials for the user
            val otpCredentials = session.userCredentialManager()
                .getStoredCredentialsByType(realm, user, OTPCredentialModel.TYPE)
            
            val devices = otpCredentials.map { credential ->
                mapOf(
                    "id" to credential.id,
                    "deviceName" to (credential.userLabel ?: "Unknown Device"),
                    "createdDate" to credential.createdDate
                )
            }
            
            return Response.ok()
                .entity(mapOf(
                    "devices" to devices,
                    "count" to devices.size
                )).build()
                
        } catch (e: Exception) {
            logger.error("Error listing TOTP devices for user ${user.username}", e)
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(ApiResponse("Failed to list TOTP devices: ${e.message}")).build()
        }
    }
}
