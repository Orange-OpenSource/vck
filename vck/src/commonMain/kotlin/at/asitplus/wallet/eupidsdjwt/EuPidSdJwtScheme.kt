package at.asitplus.wallet.eupidsdjwt

import at.asitplus.wallet.lib.InternalHelpers.mandatoryElements
import at.asitplus.wallet.lib.InternalHelpers.optionalElements
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationList
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDefinition
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocument
import at.asitplus.wallet.sdjwt.SdJwtVcType

@Deprecated(
    "Replace with type metadata document",
    level = DeprecationLevel.ERROR
)
object EuPidSdJwtScheme


val EuPidSdJwtMetadataDocument: Pair<SdJwtVcType, SdJwtTypeMetadataDocument> =
    SdJwtVcType("urn:eudi:pid:1") to SdJwtTypeMetadataDocument(
        originalBytes = ByteArray(0),
        definition = SdJwtTypeMetadataDefinition(
            vct = SdJwtVcType("urn:eudi:pid:1"),
            claims = SdJwtTypeMetadataClaimInformationList(
                mandatoryElements(
                    EuPidSdJwtDataElements.FAMILY_NAME,
                    EuPidSdJwtDataElements.GIVEN_NAME,
                    EuPidSdJwtDataElements.BIRTH_DATE,
                    EuPidSdJwtDataElements.NATIONALITIES,
                    EuPidSdJwtDataElements.EXPIRY_DATE,
                    EuPidSdJwtDataElements.ISSUING_AUTHORITY,
                    EuPidSdJwtDataElements.ISSUING_COUNTRY,
                ) + optionalElements(
                    EuPidSdJwtDataElements.PLACE_OF_BIRTH_COUNTRY,
                    EuPidSdJwtDataElements.PLACE_OF_BIRTH_REGION,
                    EuPidSdJwtDataElements.PLACE_OF_BIRTH_LOCALITY,
                    EuPidSdJwtDataElements.ADDRESS_FORMATTED,
                    EuPidSdJwtDataElements.ADDRESS_COUNTRY,
                    EuPidSdJwtDataElements.ADDRESS_REGION,
                    EuPidSdJwtDataElements.ADDRESS_LOCALITY,
                    EuPidSdJwtDataElements.ADDRESS_POSTAL_CODE,
                    EuPidSdJwtDataElements.ADDRESS_STREET,
                    EuPidSdJwtDataElements.ADDRESS_HOUSE_NUMBER,
                    EuPidSdJwtDataElements.FAMILY_NAME_BIRTH,
                    EuPidSdJwtDataElements.GIVEN_NAME_BIRTH,
                    EuPidSdJwtDataElements.EMAIL,
                    EuPidSdJwtDataElements.PHONE_NUMBER,
                    EuPidSdJwtDataElements.PORTRAIT,
                    EuPidSdJwtDataElements.ISSUANCE_DATE,
                    EuPidSdJwtDataElements.PERSONAL_ADMINISTRATIVE_NUMBER,
                    EuPidSdJwtDataElements.SEX,
                    EuPidSdJwtDataElements.DOCUMENT_NUMBER,
                    EuPidSdJwtDataElements.ISSUING_JURISDICTION,
                    EuPidSdJwtDataElements.TRUST_ANCHOR,
                )
            )
        ),
    )
