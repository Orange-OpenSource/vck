package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.ClaimDescription
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.OpenId4VciClaimsPathPointer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.ExtractedIsoMdocCredentialScheme
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.maps.shouldContainKey
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

val CredentialSchemeMappingTest by matrixSuite {

    val mapper = DefaultCredentialSchemeMapper()

    test("AtomicAttribute in plain JWT") {
        val expectedKey = "${AtomicAttribute2023.vcType}#${CredentialFormatEnum.JWT_VC.text}"
        mapper.toCredentialIdentifier(AtomicAttribute2023, PLAIN_JWT) shouldBe expectedKey
        mapper.map(AtomicAttribute2023).shouldContainKey(expectedKey)
        mapper.decodeFromCredentialIdentifier(expectedKey) shouldBe Pair(AtomicAttribute2023, PLAIN_JWT)
    }

    test("AtomicAttribute in SD-JWT") {
        val expectedKey = "${AtomicAttribute2023.sdJwtType}#${CredentialFormatEnum.DC_SD_JWT.text}"
        mapper.toCredentialIdentifier(AtomicAttribute2023, SD_JWT) shouldBe expectedKey
        mapper.map(AtomicAttribute2023).shouldContainKey(expectedKey)
        mapper.decodeFromCredentialIdentifier(expectedKey) shouldBe Pair(AtomicAttribute2023, SD_JWT)
    }

    test("AtomicAttribute in ISO mDoc") {
        val expectedKey = AtomicAttribute2023.isoDocType
        mapper.toCredentialIdentifier(AtomicAttribute2023, ISO_MDOC) shouldBe expectedKey
        mapper.map(AtomicAttribute2023).shouldContainKey(expectedKey)
        mapper.decodeFromCredentialIdentifier(expectedKey) shouldBe Pair(AtomicAttribute2023, ISO_MDOC)
    }

    test("AtomicAttribute ISO claims are namespace-qualified") {
        val format = mapper.map(AtomicAttribute2023)[AtomicAttribute2023.isoDocType].shouldNotBeNull()
        val paths = format.credentialMetadata?.claimDescription.shouldNotBeNull().map { it.path }
        paths shouldContain
                OpenId4VciClaimsPathPointer(AtomicAttribute2023.isoNamespace, AtomicAttribute2023.CLAIM_GIVEN_NAME)
        // The un-qualified JSON-style path must not be advertised for the ISO mdoc representation.
        paths shouldNotContain OpenId4VciClaimsPathPointer(AtomicAttribute2023.CLAIM_GIVEN_NAME)
    }

    test("already namespace-qualified ISO claims are not double-prefixed") {
        val namespace = "org.iso.18013.5.1"
        val scheme = ExtractedIsoMdocCredentialScheme(
            isoDocType = "org.iso.18013.5.1.mDL",
            isoNamespace = namespace,
            claimDescriptions = setOf(ClaimDescription(OpenId4VciClaimsPathPointer(namespace, "given_name"))),
        )
        val (_, format) = scheme.toIsoMdocSupportedCredentialFormat("identifier")
        format.credentialMetadata?.claimDescription.shouldNotBeNull().map { it.path } shouldBe
                listOf(OpenId4VciClaimsPathPointer(namespace, "given_name"))
    }

    test("unknown scheme in plain JWT") {
        val key = "${randomString()}#${CredentialFormatEnum.JWT_VC.text}"
        mapper.decodeFromCredentialIdentifier(key).shouldBeNull()
    }

    test("unknown scheme in SD-JWT") {
        val key = "${randomString()}#${CredentialFormatEnum.DC_SD_JWT.text}"
        mapper.decodeFromCredentialIdentifier(key).shouldBeNull()
    }

    test("unknown scheme in ISO mDoc") {
        val key = "${randomString()}#${CredentialFormatEnum.MSO_MDOC.text}"
        mapper.decodeFromCredentialIdentifier(key).shouldBeNull()
    }

    test("unknown scheme, no format") {
        mapper.decodeFromCredentialIdentifier(randomString()).shouldBeNull()
    }
}
