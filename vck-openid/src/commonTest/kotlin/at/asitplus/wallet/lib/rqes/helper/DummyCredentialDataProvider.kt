package at.asitplus.wallet.lib.rqes.helper

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtDataElements
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import kotlinx.datetime.LocalDate
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

object DummyCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    fun getCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: CredentialScheme,
        representation: CredentialRepresentation,
    ): KmmResult<CredentialToBeIssued> = catching {
        val issuance = Clock.System.now()
        val expiration = issuance + defaultLifetime
        if (credentialScheme.sdJwtType != EU_PID_SD_JWT_VCT) {
            throw NotImplementedError()
        }
        if (representation != SD_JWT) {
            throw NotImplementedError()
        }

        val familyName = "Musterfrau"
        val givenName = "Maria"
        val birthDate = LocalDate.parse("1970-01-01")
        val issuingCountry = "AT"
        val nationality = "FR"
        CredentialToBeIssued.VcSd(
            claims = with(EuPidSdJwtDataElements) {
                listOfNotNull(
                    ClaimToBeIssued(FAMILY_NAME, familyName),
                    ClaimToBeIssued(FAMILY_NAME_BIRTH, familyName),
                    ClaimToBeIssued(GIVEN_NAME, givenName),
                    ClaimToBeIssued(GIVEN_NAME_BIRTH, givenName),
                    ClaimToBeIssued(BIRTH_DATE, birthDate),
                    ClaimToBeIssued(NATIONALITIES, listOf(nationality)),
                    ClaimToBeIssued(ISSUANCE_DATE, issuance),
                    ClaimToBeIssued(EXPIRY_DATE, expiration),
                    ClaimToBeIssued(ISSUING_COUNTRY, issuingCountry),
                    ClaimToBeIssued(ISSUING_AUTHORITY, issuingCountry),
                )
            },
            expiration = expiration,
            scheme = credentialScheme as SdJwtCredentialScheme,
            subjectPublicKey = subjectPublicKey,
            userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
            sdAlgorithm = supportedSdAlgorithms.random(),
        )
    }

}