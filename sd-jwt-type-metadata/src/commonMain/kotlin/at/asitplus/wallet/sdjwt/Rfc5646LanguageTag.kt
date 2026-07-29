package at.asitplus.wallet.sdjwt

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * See [RFC5646](https://datatracker.ietf.org/doc/html/rfc5646)
 */
@Serializable
@JvmInline
value class Rfc5646LanguageTag(
    val caseInsensitiveString: CaseInsensitiveString,
) {
    init {
        // TODO: implement proper grammar validation?
    }

    constructor(string: String) : this(CaseInsensitiveString(string))

    val string: String
        get() = caseInsensitiveString.string
}
