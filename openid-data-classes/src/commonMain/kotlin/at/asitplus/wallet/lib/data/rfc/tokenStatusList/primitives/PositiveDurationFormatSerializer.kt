package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.serialization.FormatTransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.serializer
import kotlin.time.Duration

object PositiveDurationFormatSerializer : KSerializer<PositiveDuration> by FormatTransformingSerializerTemplate(
    descriptor = Duration.serializer().descriptor,
    jsonTransformer = PositiveDurationSecondsJsonNumberSerializer,
    cborTransformer = PositiveDurationSecondsULongSerializer
)