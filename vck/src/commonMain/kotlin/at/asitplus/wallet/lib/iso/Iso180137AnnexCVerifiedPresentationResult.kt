package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.data.IsoDocumentParsed

@Deprecated("Use Iso180137AnnexCWrapper and DcApiVerifier instead")
data class Iso180137AnnexCVerifiedPresentationResult(
    val documents: Collection<IsoDocumentParsed>,
)