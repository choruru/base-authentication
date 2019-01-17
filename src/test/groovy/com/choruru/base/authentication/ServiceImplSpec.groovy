package com.choruru.base.authentication

import choruru.base.authentication.*
import io.grpc.inprocess.InProcessChannelBuilder
import io.grpc.inprocess.InProcessServerBuilder
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

@SpringBootTest
class ServiceImplSpec extends Specification {

    // Beans
    @Autowired
    ServiceImpl service

    @Autowired
    PasswordValidationConfiguration injectedPasswordValidationConfiguration

    // Shared fields
    @Shared
    Boolean initialized = false

    @Shared
    AuthenticationServiceGrpc.AuthenticationServiceBlockingStub stub

    @Shared
    PasswordValidationConfiguration passwordValidationConfiguration

    @Shared
    String validEmail = "choruru@choruru.com"

    @Shared
    String validPassword

    def setup() {
        if (!initialized) {
            def serverName = InProcessServerBuilder.generateName()
            InProcessServerBuilder
                    .forName(serverName)
                    .directExecutor()
                    .addService(service)
                    .build()
                    .start()

            stub = AuthenticationServiceGrpc.newBlockingStub(
                    InProcessChannelBuilder
                            .forName(serverName)
                            .directExecutor()
                            .build())

            passwordValidationConfiguration = injectedPasswordValidationConfiguration
            validPassword = "a" * passwordValidationConfiguration.minLength
            initialized = true
        }
    }

    def "dummy test to initialize static fields with Spring beans"() {
        expect: true
    }

    @Unroll
    def "signUp() : #TESTCASE"() {
        when:
        def signUpRes = stub.signUp(SignUpReq.newBuilder().setEmail(EMAIL).setPassword(PASSWORD).build())

        then:
        signUpRes.errorCount == ERROR_CNT

        cleanup:
        if (signUpRes.errorCount == 0) {
            stub.leave(LeaveReq.newBuilder().setJwt(signUpRes.jwt).build())
        }

        where:
        TESTCASE                                         | EMAIL      | PASSWORD                                              | ERROR_CNT
        "Sign up succeeds with valid email and password" | validEmail | validPassword                                         | 0
        "Sign up fails with empty email"                 | ""         | validPassword                                         | 1
        "Sign up fails with empty password"              | validEmail | ""                                                    | 2
        "Sign up fails with short password"              | validEmail | "a" * (passwordValidationConfiguration.minLength - 1) | 1
        "Sign up fails with long password"               | validEmail | "a" * (passwordValidationConfiguration.maxLength + 1) | 1
    }

    def "confirmSignUp()"() {
        given:
        def signUpRes = stub.signUp(SignUpReq.newBuilder().setEmail(validEmail).setPassword(validPassword).build())
        def confirmSignUpRes = stub.confirmSignUp(ConfirmSignUpReq.newBuilder().setJwt(signUpRes.jwt).build())

        when:
        def emptyJwtConfirmSignUpRes = stub.confirmSignUp(ConfirmSignUpReq.newBuilder().setJwt("").build())

        then:
        confirmSignUpRes.errorCount == 0
        emptyJwtConfirmSignUpRes.errorCount == 1

        cleanup:
        stub.leave(LeaveReq.newBuilder().setJwt(confirmSignUpRes.jwt).build())
    }

    def "authenticateByJwt"() {
        given:
        def signUpRes = stub.signUp(SignUpReq.newBuilder().setEmail(validEmail).setPassword(validPassword).build())
        def confirmSignUpRes = stub.confirmSignUp(ConfirmSignUpReq.newBuilder().setJwt(signUpRes.jwt).build())

        when:
        def jwtAuthenticateRes = stub.authenticateByJwt(JwtAuthenticateReq.newBuilder().setJwt(confirmSignUpRes.jwt).build())
        def emptyJwtAuthenticateRes = stub.authenticateByJwt(JwtAuthenticateReq.newBuilder().setJwt("").build())

        then:
        jwtAuthenticateRes.errorCount == 0
        emptyJwtAuthenticateRes.errorCount == 1

        cleanup:
        stub.leave(LeaveReq.newBuilder().setJwt(jwtAuthenticateRes.jwt).build())
    }

    @Unroll
    def "authenticateByPassword() : #TESTCASE"() {
        given:
        def signUpRes = stub.signUp(SignUpReq.newBuilder().setEmail(validEmail).setPassword(validPassword).build())
        def confirmSignUpRes = stub.confirmSignUp(ConfirmSignUpReq.newBuilder().setJwt(signUpRes.jwt).build())

        when:
        def pwAuthenticateRes = stub.authenticateByPassword(PasswordAuthenticateReq.newBuilder().setEmail(EMAIL).setPassword(PASSWORD).build())

        then:
        pwAuthenticateRes.errorCount == EXPECTED

        cleanup:
        stub.leave(LeaveReq.newBuilder().setJwt(confirmSignUpRes.jwt).build())

        where:
        TESTCASE         | EMAIL      | PASSWORD         | EXPECTED
        "Normal"         | validEmail | validPassword    | 0
        "Wrong Email"    | ""         | validPassword    | 1
        "Wrong Password" | validEmail | "wrong password" | 1
    }

}
