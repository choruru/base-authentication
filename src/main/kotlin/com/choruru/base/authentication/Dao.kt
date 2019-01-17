package com.choruru.base.authentication

import choruru.base.authentication.Error
import choruru.base.authentication.UserErrorMessage
import mu.KotlinLogging
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Repository
import org.springframework.stereotype.Service
import javax.persistence.Entity
import javax.persistence.Id

@Entity
data class Authentication(@Id val email: String = "", val encodedPassword: String = "", val authorized: Boolean = false)

@Repository
interface AuthenticationRepository : JpaRepository<Authentication, String>

interface Dao {
    fun validate(email: String, rawPassword: String): List<Error>
    fun save(email: String, rawPassword: String): Authentication?
    fun authorizeUser(email: String): Authentication?
    fun deauthorizeUser(email: String): Authentication?
    fun deleteByEmail(email: String): Boolean
    fun findByEmail(email: String): Authentication?
}

@Service
class PostgreSqlDao(
        @Autowired val authenticationRepository: AuthenticationRepository,
        @Autowired val bCryptPasswordEncoder: BCryptPasswordEncoder,
        @Autowired val passwordValidationConfiguration: PasswordValidationConfiguration)
    : Dao {

    private val logger = KotlinLogging.logger {}

    override fun validate(email: String, rawPassword: String): List<Error> {
        val errorList = mutableListOf<Error>()

        if (email.isBlank()) {
            logger.info("Email cannot be blank.")
            errorList.add(Error.newBuilder()
                    .setCode("CLIENT_INVALID-INPUT")
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Email cannot be blank")
                            .build())
                    .build())
        }
        if (rawPassword.isBlank()) {
            logger.info("Password cannot be blank.")
            errorList.add(Error.newBuilder()
                    .setCode("CLIENT_INVALID-INPUT")
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Password cannot be blank.")
                            .build())
                    .build())
        }
        if (rawPassword.length < passwordValidationConfiguration.minLength) {
            logger.info("Password length cannot be less than {}.", passwordValidationConfiguration.minLength)
            errorList.add(Error.newBuilder()
                    .setCode("CLIENT_INVALID-INPUT")
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Password length cannot be less than ${passwordValidationConfiguration.minLength}.")
                            .build())
                    .build())
        }
        if (rawPassword.length > passwordValidationConfiguration.maxLength) {
            logger.info("Password length cannot be more than {}.", passwordValidationConfiguration.maxLength)
            errorList.add(Error.newBuilder()
                    .setCode("CLIENT_INVALID-INPUT")
                    .addUserMessage(UserErrorMessage
                            .newBuilder()
                            .setLang("en")
                            .setMessage("Password length cannot be more than ${passwordValidationConfiguration.maxLength}.")
                            .build())
                    .build())
        }

        return errorList
    }

    override fun save(email: String, rawPassword: String): Authentication? {
        if (email.isBlank()) {
            logger.info("Email cannot be blank.")
            return null
        }
        if (rawPassword.isBlank()) {
            logger.info("Password cannot be blank.")
            return null
        }
        if (rawPassword.length < passwordValidationConfiguration.minLength) {
            logger.info("Password length cannot be less than {}.", passwordValidationConfiguration.minLength)
            return null
        }
        if (rawPassword.length > passwordValidationConfiguration.maxLength) {
            logger.info("Password length cannot be more than {}.", passwordValidationConfiguration.maxLength)
            return null
        }
        val encodedPassword = bCryptPasswordEncoder.encode(rawPassword)
        return authenticationRepository.save(Authentication(email, encodedPassword))
    }

    override fun authorizeUser(email: String): Authentication? {
        val authentication = this.findByEmail(email) ?: return null
        return authenticationRepository.save(authentication.copy(authorized = true))
    }

    override fun deauthorizeUser(email: String): Authentication? {
        val authentication = this.findByEmail(email) ?: return null
        return authenticationRepository.save(authentication.copy(authorized = false))
    }

    override fun deleteByEmail(email: String): Boolean {
        return try {
            authenticationRepository.deleteById(email)
            true
        } catch (ex: Exception) {
            logger.info("No entity found for email {}.", email)
            false
        }
    }

    override fun findByEmail(email: String): Authentication? {
        return try {
            authenticationRepository.getOne(email)
        } catch (ex: Exception) {
            logger.info("No entity found for email {}.", email)
            null
        }
    }

}
