package at.asitplus.wallet.lib.openid

import at.asitplus.wallet.lib.data.IsoDocumentParsed

/** Result of validating a DCAPI response, see [DcApiVerifier.validateAuthnResponse] */
sealed interface DcApiResponseResult

/**
 * Result of validating an ISO 18013-7 Annex C response, see [DcApiVerifier.validateAuthnResponse]
 * and [DcApiCreationOptions.Iso180137AnnexC]
 */
data class Iso180137AnnexCWrapper(
    val documents: Collection<IsoDocumentParsed>
) : DcApiResponseResult