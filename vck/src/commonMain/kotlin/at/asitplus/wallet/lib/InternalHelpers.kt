package at.asitplus.wallet.lib

import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformation
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationPath
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationPathSegmentName

internal object InternalHelpers {

    internal fun mandatoryElements(vararg elements: String) = elements.map {
        SdJwtTypeMetadataClaimInformation(
            path = SdJwtTypeMetadataClaimInformationPath(
                it.split("\\.").map { SdJwtTypeMetadataClaimInformationPathSegmentName(it) }),
            isMandatory = true
        )
    }

    internal fun mandatoryElementsIso(namespace: String, vararg elements: String) = elements.map {
        SdJwtTypeMetadataClaimInformation(
            path = SdJwtTypeMetadataClaimInformationPath(
                SdJwtTypeMetadataClaimInformationPathSegmentName(namespace),
                SdJwtTypeMetadataClaimInformationPathSegmentName(it)
            ),
            isMandatory = true
        )
    }

    internal fun optionalElements(vararg elements: String) = elements.map {
        SdJwtTypeMetadataClaimInformation(
            path = SdJwtTypeMetadataClaimInformationPath(
                it.split("\\.").map { SdJwtTypeMetadataClaimInformationPathSegmentName(it) }),
            isMandatory = false
        )
    }

    internal fun optionalElementsIso(namespace: String, vararg elements: String) = elements.map {
        SdJwtTypeMetadataClaimInformation(
            path = SdJwtTypeMetadataClaimInformationPath(
                SdJwtTypeMetadataClaimInformationPathSegmentName(namespace),
                SdJwtTypeMetadataClaimInformationPathSegmentName(it)
            ),
            isMandatory = false
        )
    }
}