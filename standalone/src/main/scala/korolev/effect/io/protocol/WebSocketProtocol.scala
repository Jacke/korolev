package korolev.effect.io.protocol

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

import korolev.data.ByteVector
import korolev.effect.{Decoder, Effect, Stream}
import korolev.effect.io.LazyBytes
import korolev.effect.syntax._

import korolev.server.Request.RequestHeader
import korolev.server.Response.Status
import korolev.server.{Headers, Request, Response}

import scala.annotation.{switch, tailrec}

/**
  * @see https://tools.ietf.org/html/rfc6455
  */
object WebSocketProtocol {

  final val GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

  // https://tools.ietf.org/html/rfc6455#section-11.8
  final val OpContinuation = 0
  final val OpText = 1
  final val OpBinary = 2
  final val OpConnectionClose = 8
  final val OpPing = 9
  final val OpPong = 10


  final case class Intention(key: String)

  sealed trait Frame {
    def opcode: Int
    def fin: Boolean
  }

  object Frame {
    sealed trait Merged extends Frame {
      def append(data: ByteVector, fin: Boolean): Merged
    }

    final case class Unspecified(fin: Boolean, opcode: Int, payload: ByteVector) extends Merged {
      def append(data: ByteVector, fin: Boolean): Unspecified =
        copy(fin = fin, payload = payload ++ data)
    }
    final case class Continuation(payload: ByteVector, fin: Boolean) extends Frame {
      final val opcode = OpContinuation
    }
    final case class Binary(payload: ByteVector, fin: Boolean = true) extends Merged {
      final val opcode = OpBinary
      def append(data: ByteVector, fin: Boolean): Binary =
        copy(fin = fin, payload = payload ++ data)
    }
    final case class Text(payload: ByteVector, fin: Boolean = true) extends Merged {
      lazy val utf8: String = payload.utf8String
      final val opcode = OpText
      def append(data: ByteVector, fin: Boolean): Text =
        copy(fin = fin, payload = payload ++ data)
    }
    case object ConnectionClose extends Merged {
      final val opcode = OpConnectionClose
      final val fin = true
      def append(data: ByteVector, fin: Boolean): ConnectionClose.type = this
    }
    case object Ping extends Merged {
      final val opcode = OpPing
      final val fin = true
      def append(data: ByteVector, fin: Boolean): Ping.type = this
    }
    case object Pong extends Merged {
      final val opcode = OpPong
      final val fin = true
      def append(data: ByteVector, fin: Boolean): Pong.type = this
    }
  }

  sealed trait DecodingState

  object DecodingState {
    val begin: DecodingState = Begin
    case object Begin extends DecodingState
    case class ShortLength(fin: Boolean, mask: Boolean, opcode: Int) extends DecodingState
    case class LongLength(fin: Boolean, mask: Boolean, opcode: Int) extends DecodingState
    case class Payload(fin: Boolean, containMask: Boolean, opcode: Int, length: Long) extends DecodingState {
      lazy val offset: Long =
        if (containMask) 4
        else 0
      lazy val fullLength: Long =
        if (containMask) length + 4
        else length
    }
  }

  import DecodingState._

  def decodeFrame(data: ByteVector): ((ByteVector, DecodingState), Decoder.Action[ByteVector, Frame]) =
    decodeFrames(ByteVector.empty, Begin, data)

  @tailrec
  def decodeFrames(buffer: ByteVector,
                   state: DecodingState,
                   incoming: ByteVector): ((ByteVector, DecodingState), Decoder.Action[ByteVector, Frame]) = {

    def decodePayload(bytes: ByteVector, state: Payload): ByteVector =
      if (!state.containMask) {
        bytes.slice(0, state.fullLength)
      } else {
        val mask = bytes.slice(0, 4).mkArray
        bytes.slice(4, state.fullLength).mapI((x, i) => (x ^ mask(i % 4)).toByte)
      }

    val bytes = buffer ++ incoming
    state match {
      case Begin if bytes.length >= 2 =>
        // Enough to read length
        val firstByte = bytes(0) & 0xFF
        val secondByte = bytes(1) & 0xFF
        val fin = (firstByte & 0x80) != 0
        val opcode = firstByte & 0x0F
        val mask = (secondByte & 0x80) != 0
        val restOfBytes = bytes.slice(2)
        // Detect length encoding
        (secondByte & 0x7F: @switch) match {
          case 126 =>
            // Read 2 bytes length
            val nextState = ShortLength(fin, mask, opcode)
            decodeFrames(restOfBytes, nextState, ByteVector.empty)
          case 127 =>
            // Read 8 bytes length
            val nextState = LongLength(fin, mask, opcode)
            decodeFrames(restOfBytes, nextState, ByteVector.empty)
          case length =>
            // Tiny length. Read payload
            val nextState = Payload(fin, mask, opcode, length)
            decodeFrames(restOfBytes, nextState, ByteVector.empty)
        }
      case s: ShortLength if bytes.length >= 2 =>
        val length = bytes.readShort(0) & 0xFFFF
        val nextState = Payload(s.fin, s.mask, s.opcode, length)
        decodeFrames(bytes.slice(2), nextState, ByteVector.empty)
      case s: LongLength if bytes.length >= 8 =>
        val length = bytes.readLong(0)
        val nextState = Payload(s.fin, s.mask, s.opcode, length)
        decodeFrames(bytes.slice(8), nextState, ByteVector.empty)
      case s: Payload if bytes.length >= s.fullLength =>
        val payloadBytes = decodePayload(bytes, s)
        val frame = (s.opcode: @switch) match {
          case OpContinuation => Frame.Continuation(payloadBytes, s.fin)
          case OpBinary => Frame.Binary(payloadBytes, s.fin)
          case OpText => Frame.Text(payloadBytes, s.fin)
          case OpConnectionClose => Frame.ConnectionClose
          case OpPing => Frame.Ping
          case OpPong => Frame.Pong
          case _ => Frame.Unspecified(s.fin, s.opcode, payloadBytes)
        }
        bytes.slice(s.fullLength) match {
          case ByteVector.Empty => ((ByteVector.empty, Begin), Decoder.Action.Push(frame))
          case restOfBytes => ((ByteVector.empty, Begin), Decoder.Action.Fork(frame, restOfBytes))
        }
      case state =>
        // Not enough bytes in buffer. Keep buffering
        ((bytes, state), Decoder.Action.TakeNext)
    }
  }

  /**
    * https://tools.ietf.org/html/rfc6455#section-5.4
    */
  def mergeFrames(buffer: Option[Frame.Merged], incoming: Frame): (Option[Frame.Merged], Decoder.Action[Frame, Frame]) =
    (buffer, incoming) match {
      case (_, Frame.ConnectionClose | Frame.Ping | Frame.Pong) =>
        // Control frames MAY be injected in
        // the middle of a fragmented message.
        (buffer, Decoder.Action.Push(incoming))
      case (None, i) if i.fin => (None, Decoder.Action.Push(i))
      case (None, i: Frame.Text) if !i.fin => (Some(i), Decoder.Action.TakeNext)
      case (None, i: Frame.Binary) if !i.fin => (Some(i), Decoder.Action.TakeNext)
      case (None, i: Frame.Unspecified) if !i.fin => (Some(i), Decoder.Action.TakeNext)
      case (Some(buffer), i: Frame.Continuation) if !i.fin =>
        (Some(buffer.append(i.payload, fin = false)), Decoder.Action.TakeNext)
      case (Some(buffer), i: Frame.Continuation) if i.fin =>
        (None, Decoder.Action.Push(buffer.append(i.payload, fin = true)))
      case _ => throw new IllegalStateException(s"Fragmentation in WebSocket is invalid. Received $incoming after $buffer")
    }

  def encodeFrame(frame: Frame, maybeMask: Option[Int]): ByteVector = frame match {
    case Frame.Pong | Frame.Ping | Frame.ConnectionClose => encodeFrame(fin = true, maybeMask, frame.opcode, ByteVector.empty)
    case Frame.Continuation(payload, fin) => encodeFrame(fin, maybeMask, frame.opcode, payload)
    case Frame.Binary(payload, fin) => encodeFrame(fin, maybeMask, frame.opcode, payload)
    case Frame.Text(payload, fin) => encodeFrame(fin, maybeMask, frame.opcode, payload)
    case Frame.Unspecified(fin, opcode, payload) => encodeFrame(fin, maybeMask, opcode, payload)
  }

  def encodeFrame(fin: Boolean, maybeMask: Option[Int], opcode: Int, payload: ByteVector): ByteVector = {
    def choseLength[T](l: Long => T, s: Long => T, t: Long => T): T = payload.length match {
      case x if x > 65535 => l(x)
      case x if x > 125 => s(x)
      case x => t(x)
    }
    val maskSize = maybeMask.fold(0)(_ => 4)
    val buffer = ByteBuffer.allocate(2 + choseLength(_ => 8, _ => 2, _ => 0) + maskSize)
    buffer.put(((if (fin) 1 << 7 else 0) | opcode).toByte)
    buffer.put(((if (maybeMask.nonEmpty) 1 << 7 else 0 ) | choseLength[Int](_ => 127, _ => 126, _.toInt)).toByte)
    choseLength(
      x => buffer.putLong(x),
      x => buffer.putShort((x & 0xFFFF).toShort),
      _ => buffer
    )
    maybeMask match {
      case None => buffer.array() +: payload
      case Some(mask) =>
        val array = buffer.array()
        val o = array.length - 4
        buffer.putInt(mask)
        array +: payload.mapI { (x, i) =>
          (x ^ array(o + (i % 4))).toByte
        }
    }
  }

  def findIntention(request: RequestHeader): Option[Intention] =
    request.header(Headers.SecWebSocketKey).map(Intention)

  def handshake[T](response: Response[T], intention: Intention): Response[T] = {
    val kg = s"${intention.key}$GUID"
    val sha1 = MessageDigest.getInstance("SHA-1") // TODO optimize me
    val hash = sha1.digest(kg.getBytes(StandardCharsets.US_ASCII))
    val accept = Base64.getEncoder.encodeToString(hash)
    response.copy(
      status = Status.SwitchingProtocols,
      headers =
        (Headers.SecWebSocketAccept -> accept) +:
        Headers.ConnectionUpgrade +:
        Headers.UpgradeWebSocket +:
          response.headers
    )
  }

  /**
    * Upgrade Request/Response with raw bytes to WebSocket protocol and
    * insert handshake headers. Fragments will be merged to single frames.
    */
  def upgrade[F[_]: Effect](intention: Intention)
                           (f: Request[Stream[F, Frame]] => F[Response[Stream[F, Frame.Merged]]]): Request[LazyBytes[F]] => F[Response[LazyBytes[F]]] = f
      .compose[Request[LazyBytes[F]]] { request =>
        val messages = Decoder(request.body.chunks.map(ByteVector(_)))
          .decode((ByteVector.empty, DecodingState.begin)) {
            case ((buffer, state), incoming) =>
              decodeFrames(buffer, state, incoming)
          }
          .decode(Option.empty[Frame.Merged])(mergeFrames)
        request.copy(body = messages)
      }
      .andThen[F[Response[LazyBytes[F]]]] { responseF =>
        responseF.map { response =>
          val upgradedBody = response.body.map(m => encodeFrame(m, None).mkArray)
          handshake(response, intention).copy(body = LazyBytes(upgradedBody, None))
        }
      }
}
