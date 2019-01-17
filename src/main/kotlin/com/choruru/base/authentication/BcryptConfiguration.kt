package com.choruru.base.authentication

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Component

@Configuration
class BcryptConfiguration {
    @Bean
    fun getBcryptEncoder(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder()
    }
}


@Component
class PasswordValidationConfiguration {
    @Value("\${authentication.password.minLength:10}")
    var minLength: Int = 10

    @Value("\${authentication.password.maxLength:32}")
    var maxLength: Int = 32
}
