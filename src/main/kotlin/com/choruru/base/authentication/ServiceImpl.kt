package com.choruru.base.authentication

import choruru.base.authentication.*
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import io.grpc.stub.StreamObserver
import mu.KotlinLogging
import org.lognet.springboot.grpc.GRpcService
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.io.UnsupportedEncodingException
import java.util.*


private const val EXPIRATION_TIME_FOR_SESSION = 60L * 30L
private const val EXPIRATION_TIME_FOR_SIGN_UP = 60L * 60L * 3L
private const val EXPIRATION_TIME_FOR_REMEMBER_ME = 60L * 60L * 24L * 7L

private val bCryptPasswordEncoder = BCryptPasswordEncoder()

@GRpcService
class ServiceImpl(val dao: PostgreSqlDao) : AuthenticationServiceGrpc.AuthenticationServiceImplBase() {
    private val logger = KotlinLogging.logger {}

    @Value("\${authentication.jwt.secret:secret}")
    private var secretKey = "secret"


    override fun signUp(request: SignUpReq, responseObserver: StreamObserver<SignUpRes>) {
        val errorList = mutableListOf<Error>()

        val issuedAt = Date()
        val notBefore = Date(issuedAt.time)
        val expiresAt = Date(issuedAt.time + EXPIRATION_TIME_FOR_SIGN_UP)

        var token = ""
        try {
            val algorithm = Algorithm.HMAC256(secretKey)
            token = JWT.create()
                    .withJWTId("SIGN-UP")
                    .withIssuedAt(issuedAt)
                    .withNotBefore(notBefore)
                    .withExpiresAt(expiresAt)
                    .withClaim("email", request.email)
                    .sign(algorithm)
        } catch (ex: UnsupportedEncodingException) {
            logger.error("Token generation failed. {}", ex)
            errorList.add(Error.newBuilder()
                    .setCode("SERVER_INVALID-INPUT")
                    .setMessage(ex.toString())
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Server Error")
                            .build())
                    .build())
        }

        if (errorList.isEmpty()) {
            val errorListFromDao = dao.validate(request.email, request.password)
            errorList.addAll(errorListFromDao)
        }

        if (errorList.isEmpty()) {
            dao.save(request.email, request.password)
        }

        val response = SignUpRes.newBuilder()
                .addAllError(errorList)
                .setJwt(token)
                .build()

        responseObserver.onNext(response)
        responseObserver.onCompleted()
    }

    override fun confirmSignUp(request: ConfirmSignUpReq, responseObserver: StreamObserver<ConfirmSignUpRes>) {
        val errorList = mutableListOf<Error>()

        var email = ""

        try {
            val algorithm = Algorithm.HMAC256(secretKey)
            val verifier = JWT.require(algorithm).build()
            val jwtObj = verifier.verify(request.jwt)

            if (jwtObj.id != "SIGN-UP") {
                errorList.add(Error.newBuilder()
                        .setCode("SERVER_INTERNAL-ERROR")
                        .setMessage("Invalid jwt token id")
                        .addUserMessage(UserErrorMessage
                                .newBuilder()
                                .setLang("en")
                                .setMessage("Server error")
                                .build())
                        .build())
            }

            if (jwtObj.getClaim("email").isNull) {
                errorList.add(Error.newBuilder()
                        .setCode("SERVER_INTERNAL-ERROR")
                        .setMessage("jwt token does not contain email")
                        .addUserMessage(UserErrorMessage
                                .newBuilder()
                                .setLang("en")
                                .setMessage("Server error")
                                .build())
                        .build())
            } else {
                email = jwtObj.getClaim("email").asString()!!
            }
        } catch (ex: UnsupportedEncodingException) {
            errorList.add(Error.newBuilder()
                    .setCode("SERVER_INTERNAL-ERROR")
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Server Error")
                            .build())
                    .build())
        } catch (ex: JWTVerificationException) {
            errorList.add(Error.newBuilder()
                    .setCode("CLIENT_INVALID-INPUT")
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Invalid email")
                            .build())
                    .build())
        }


        var token = ""
        if (errorList.isEmpty()) {
            val user = dao.authorizeUser(email)
            if (user == null) {
                errorList.add(Error.newBuilder()
                        .setCode("SERVER_INTERNAL-ERROR")
                        .setMessage("User does not exist")
                        .addUserMessage(UserErrorMessage
                                .newBuilder()
                                .setLang("en")
                                .setMessage("Server Error")
                                .build())
                        .build())
            } else {
                val issuedAt = Date()
                val notBefore = Date(issuedAt.time)
                val expiresAt = Date(issuedAt.time + EXPIRATION_TIME_FOR_SESSION)

                try {
                    val algorithm = Algorithm.HMAC256(secretKey)
                    token = JWT.create()
                            .withJWTId("SIGN-IN")
                            .withIssuedAt(issuedAt)
                            .withNotBefore(notBefore)
                            .withExpiresAt(expiresAt)
                            .withClaim("email", email)
                            .sign(algorithm)
                } catch (ex: UnsupportedEncodingException) {
                    logger.error("Token generation failed. {}", ex)
                    errorList.add(Error.newBuilder()
                            .setCode("SERVER_INVALID-INPUT")
                            .addUserMessage(UserErrorMessage
                                    .newBuilder()
                                    .setLang("en")
                                    .setMessage("Server Error")
                                    .build())
                            .build())
                }
            }
        }

        val response =
                ConfirmSignUpRes.newBuilder()
                        .addAllError(errorList)
                        .setJwt(token)
                        .build()

        responseObserver.onNext(response)
        responseObserver.onCompleted()

    }

    override fun authenticateByPassword(request: PasswordAuthenticateReq, responseObserver: StreamObserver<AuthenticateRes>) {

        val errorList = mutableListOf<Error>()

        val user = dao.findByEmail(request.email)

        if (user?.encodedPassword == null) {
            errorList.add(Error.newBuilder()
                    .setCode("CLIENT_INVALID-INPUT")
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Email is not registered.")
                            .build())
                    .build())
        }

        if (errorList.isEmpty()) {
            val isPasswordMatched = bCryptPasswordEncoder.matches(request.password, user?.encodedPassword)
            if (!isPasswordMatched) {
                errorList.add(Error.newBuilder()
                        .setCode("CLIENT_INVALID-INPUT")
                        .addUserMessage(UserErrorMessage
                                .newBuilder()
                                .setLang("en")
                                .setMessage("Password does not match.")
                                .build())
                        .build())
            }
        }

        var token = ""
        if (errorList.isEmpty()) {
            val issuedAt = Date()
            val notBefore = Date(issuedAt.time)
            val expiresAt = Date(issuedAt.time + EXPIRATION_TIME_FOR_SESSION)

            try {
                val algorithm = Algorithm.HMAC256(secretKey)
                token = JWT.create()
                        .withJWTId("SIGN-IN")
                        .withIssuedAt(issuedAt)
                        .withNotBefore(notBefore)
                        .withExpiresAt(expiresAt)
                        .withClaim("email", user?.email)
                        .sign(algorithm)
            } catch (ex: UnsupportedEncodingException) {
                logger.error("Token generation failed. {}", ex)
                errorList.add(Error.newBuilder()
                        .setCode("SERVER_INVALID-INPUT")
                        .addUserMessage(UserErrorMessage
                                .newBuilder()
                                .setLang("en")
                                .setMessage("Server Error")
                                .build())
                        .build())
            }
        }

        val response =
                AuthenticateRes.newBuilder()
                        .addAllError(errorList)
                        .setIsAuthorized(!errorList.isEmpty())
                        .setJwt(token)
                        .build()

        responseObserver.onNext(response)
        responseObserver.onCompleted()
    }

    override fun authenticateByJwt(request: JwtAuthenticateReq, responseObserver: StreamObserver<AuthenticateRes>) {
        val errorList = mutableListOf<Error>()

        var email = ""

        try {
            val algorithm = Algorithm.HMAC256(secretKey)
            val verifier = JWT.require(algorithm).build()
            val jwtObj = verifier.verify(request.jwt)

            if (jwtObj.id != "SIGN-IN") {
                errorList.add(Error.newBuilder()
                        .setCode("SERVER_INTERNAL-ERROR")
                        .setMessage("Invalid jwt token id")
                        .addUserMessage(UserErrorMessage
                                .newBuilder()
                                .setLang("en")
                                .setMessage("Server error")
                                .build())
                        .build())
            }

            if (jwtObj.getClaim("email").isNull) {
                errorList.add(Error.newBuilder()
                        .setCode("SERVER_INTERNAL-ERROR")
                        .setMessage("jwt token does not contain email")
                        .addUserMessage(UserErrorMessage
                                .newBuilder()
                                .setLang("en")
                                .setMessage("Server error")
                                .build())
                        .build())
            } else {
                email = jwtObj.getClaim("email").asString()!!
            }
        } catch (ex: UnsupportedEncodingException) {
            errorList.add(Error.newBuilder()
                    .setCode("SERVER_INTERNAL-ERROR")
                    .setMessage(ex.toString())
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Server error")
                            .build())
                    .build())
        } catch (ex: JWTVerificationException) {
            errorList.add(Error.newBuilder()
                    .setCode("CLIENT_INVALID-INPUT")
                    .setMessage(ex.toString())
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Invalid email")
                            .build())
                    .build())
        }

        var token = ""
        if (errorList.isEmpty()) {
            val issuedAt = Date()
            val notBefore = Date(issuedAt.time)
            val expiresAt = Date(issuedAt.time + EXPIRATION_TIME_FOR_SESSION)

            try {
                val algorithm = Algorithm.HMAC256(secretKey)
                token = JWT.create()
                        .withJWTId("SIGN-IN")
                        .withIssuedAt(issuedAt)
                        .withNotBefore(notBefore)
                        .withExpiresAt(expiresAt)
                        .withClaim("email", email)
                        .sign(algorithm)
            } catch (ex: UnsupportedEncodingException) {
                logger.error("Token generation failed. {}", ex)
                errorList.add(Error.newBuilder()
                        .setCode("SERVER_INVALID-INPUT")
                        .addUserMessage(UserErrorMessage
                                .newBuilder()
                                .setLang("en")
                                .setMessage("Server Error")
                                .build())
                        .build())
            }
        }

        val response =
                AuthenticateRes.newBuilder()
                        .addAllError(errorList)
                        .setIsAuthorized(!errorList.isEmpty())
                        .setJwt(token)
                        .build()

        responseObserver.onNext(response)
        responseObserver.onCompleted()
    }

    override fun leave(request: LeaveReq, responseObserver: StreamObserver<LeaveRes>) {
        val errorList = mutableListOf<Error>()

        var email = ""

        try {
            val algorithm = Algorithm.HMAC256(secretKey)
            val verifier = JWT.require(algorithm).build()
            val jwtObj = verifier.verify(request.jwt)

            if (jwtObj.getClaim("email").isNull) {
                errorList.add(Error.newBuilder()
                        .setCode("SERVER_INTERNAL-ERROR")
                        .setMessage("jwt token does not contain email")
                        .addUserMessage(UserErrorMessage
                                .newBuilder()
                                .setLang("en")
                                .setMessage("Server error")
                                .build())
                        .build())
            } else {
                email = jwtObj.getClaim("email").asString()!!
            }
        } catch (ex: UnsupportedEncodingException) {
            errorList.add(Error.newBuilder()
                    .setCode("SERVER_INTERNAL-ERROR")
                    .setMessage(ex.toString())
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Server error")
                            .build())
                    .build())
        } catch (ex: JWTVerificationException) {
            errorList.add(Error.newBuilder()
                    .setCode("CLIENT_INVALID-INPUT")
                    .setMessage(ex.toString())
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Invalid email")
                            .build())
                    .build())
        }

        val isLeft = dao.deleteByEmail(email)

        if (!isLeft) {
            errorList.add(Error.newBuilder()
                    .setCode("SERVER_INTERNAL-ERROR")
                    .setMessage("dao operation failed")
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Server error")
                            .build())
                    .build())
        }

        val response = LeaveRes.newBuilder()
                .setIsLeft(isLeft)
                .addAllError(errorList)
                .build()

        responseObserver.onNext(response)
        responseObserver.onCompleted()
    }

}

