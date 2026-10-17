package rvls.spinal

import java.io.File
import scala.io.Source

/*
 * Replays an ASCII trace through a TraceBackend.
 *   roundtrip <in> <out>  FileBackend round trip
 *   jni <in> <workspace>  RvlsBackend replay: "JNI PASS" or "JNI FAIL line N: ..."
 */
object TraceReplay {
  type Bytes = Vector[Byte]

  sealed trait Event { def drive(b: TraceBackend): Unit }
  case class MemView(id: Int, readIds: Long, writeIds: Long) extends Event { def drive(b: TraceBackend) = b.newCpuMemoryView(id, readIds, writeIds) }
  case class NewCpu(hart: Int, isa: String, priv: String, physWidth: Int, pmpNum: Int, triggerCount: Int, asidWidth: Int, viewId: Int) extends Event {
    def drive(b: TraceBackend) = b.newCpu(hart, isa, priv, physWidth, pmpNum, triggerCount, asidWidth, viewId)
  }
  case class LoadElf(offset: Long, path: String) extends Event { def drive(b: TraceBackend) = b.loadElf(offset, new File(path)) }
  case class LoadBin(offset: Long, path: String) extends Event { def drive(b: TraceBackend) = b.loadBin(offset, new File(path)) }
  case class LoadBytes(offset: Long, bytes: Bytes) extends Event { def drive(b: TraceBackend) = b.loadBytes(offset, bytes.toArray) }
  case class SetPc(hart: Int, pc: Long) extends Event { def drive(b: TraceBackend) = b.setPc(hart, pc) }
  case class SetReg(hart: Int, id: Int, value: Long) extends Event { def drive(b: TraceBackend) = b.setRegister(hart, id, value) }
  case class Region(hart: Int, kind: Int, base: Long, size: Long) extends Event { def drive(b: TraceBackend) = b.addRegion(hart, kind, base, size) }
  case class Time(value: Long) extends Event { def drive(b: TraceBackend) = b.time(value) }
  case class Commit(hart: Int, pc: Long, instruction: Long) extends Event { def drive(b: TraceBackend) = b.commit(hart, pc, instruction) }
  case class Trap(hart: Int, interrupt: Boolean, code: Int) extends Event { def drive(b: TraceBackend) = b.trap(hart, interrupt, code) }
  case class TrapFields(hart: Int, interrupt: Boolean, code: Int, epc: Long, tval: Long) extends Event { def drive(b: TraceBackend) = b.trap(hart, interrupt, code, epc, tval) }
  case class WriteRf(hart: Int, kind: Int, address: Int, data: Bytes) extends Event { def drive(b: TraceBackend) = b.writeRf(hart, kind, address, data.toArray) }
  case class ReadRf(hart: Int, kind: Int, address: Int, data: Bytes) extends Event { def drive(b: TraceBackend) = b.readRf(hart, kind, address, data.toArray) }
  case class WriteVrf(hart: Int, vreg: Int, mask: Bytes, data: Bytes) extends Event { def drive(b: TraceBackend) = b.writeVrf(hart, vreg, mask.toArray, data.toArray) }
  case class WriteVs(hart: Int, value: Int) extends Event { def drive(b: TraceBackend) = b.writeVs(hart, value) }
  case class Policy(hart: Int, policy: String) extends Event { def drive(b: TraceBackend) = b.setPolicy(hart, policy) }
  case class LoadExe(hart: Int, id: Long, len: Long, addr: Long, data: Bytes) extends Event { def drive(b: TraceBackend) = b.loadExecute(hart, id, addr, len, data.toArray) }
  case class LoadCom(hart: Int, id: Long) extends Event { def drive(b: TraceBackend) = b.loadCommit(hart, id) }
  case class LoadFlush(hart: Int) extends Event { def drive(b: TraceBackend) = b.loadFlush(hart) }
  case class StoreExe(hart: Int, id: Long, len: Long, addr: Long, data: Bytes, mask: Option[Bytes]) extends Event {
    def drive(b: TraceBackend) = mask match {
      case Some(m) => b.storeExecute(hart, id, addr, len, data.toArray, m.toArray)
      case None => b.storeExecute(hart, id, addr, len, data.toArray)
    }
  }
  case class StoreCom(hart: Int, id: Long) extends Event { def drive(b: TraceBackend) = b.storeCommit(hart, id) }
  case class StoreBro(hart: Int, id: Long) extends Event { def drive(b: TraceBackend) = b.storeBroadcast(hart, id) }
  case class StoreSc(hart: Int, failure: Boolean) extends Event { def drive(b: TraceBackend) = b.storeConditional(hart, failure) }
  case class Io(hart: Int, write: Boolean, address: Long, data: Bytes, mask: Int, size: Int, error: Boolean) extends Event {
    def drive(b: TraceBackend) = b.ioAccess(hart, new TraceIo(write, address, data.toArray, mask, size, error))
  }
  case class SetInt(hart: Int, id: Int, value: Boolean) extends Event { def drive(b: TraceBackend) = b.setInterrupt(hart, id, value) }

  def hex(s: String): Long = java.lang.Long.parseUnsignedLong(s, 16)
  def bool(s: String): Boolean = s match {
    case "0" => false
    case "1" => true
    case _ => throw new IllegalArgumentException(s"bad boolean $s")
  }

  // Hex token, most significant byte first: element 0 is the rightmost pair.
  def bytes(token: String, size: Int): Bytes = {
    require(token.length == size * 2, s"data token $token is not $size bytes")
    Vector.tabulate(size)(i => Integer.parseInt(token.substring(token.length - 2 * i - 2, token.length - 2 * i), 16).toByte)
  }

  // ASCII mask token to the packed form of TraceBackend.maskHex.
  def mask(token: String, size: Int): Bytes = {
    require(token.length == (size + 3) / 4, s"mask token $token does not cover $size bytes")
    val packed = Array.fill[Byte]((size + 7) / 8)(0)
    for (d <- 0 until token.length) {
      val nibble = Integer.parseInt(token.substring(token.length - 1 - d, token.length - d), 16)
      packed(d / 2) = (packed(d / 2) | nibble << (d % 2 * 4)).toByte
    }
    packed.toVector
  }

  def parseLine(line: String): Option[Event] = {
    val t = line.trim.split("\\s+").toList
    t match {
      case Nil | "" :: Nil => None
      case head :: _ if head.startsWith("#") => None
      case "memview" :: "new" :: id :: r :: w :: Nil => Some(MemView(id.toInt, r.toLong, w.toLong))
      case "elf" :: "load" :: off :: path :: Nil => Some(LoadElf(hex(off), path))
      case "bin" :: "load" :: off :: path :: Nil => Some(LoadBin(hex(off), path))
      case "bytes" :: "load" :: off :: data => Some(LoadBytes(hex(off), data.map(v => hex(v).toByte).toVector))
      case "time" :: v :: Nil => Some(Time(v.toLong))
      case "rv" :: rest => Some(rest match {
        case "new" :: h :: isa :: priv :: phys :: pmp :: tail => tail.map(_.toInt) match {
          case view :: Nil => NewCpu(h.toInt, isa, priv, phys.toInt, pmp.toInt, 0, 0, view)
          case trig :: view :: Nil => NewCpu(h.toInt, isa, priv, phys.toInt, pmp.toInt, trig, 0, view)
          case trig :: asid :: view :: Nil => NewCpu(h.toInt, isa, priv, phys.toInt, pmp.toInt, trig, asid, view)
          case _ => throw new IllegalArgumentException(line)
        }
        case "set" :: "pc" :: h :: pc :: Nil => SetPc(h.toInt, hex(pc))
        case "set" :: "reg" :: h :: r :: v :: Nil if r.startsWith("x") => SetReg(h.toInt, r.drop(1).toInt, hex(v))
        case "region" :: "add" :: h :: k :: base :: size :: Nil => Region(h.toInt, k.toInt, hex(base), hex(size))
        case "commit" :: h :: pc :: Nil => Commit(h.toInt, hex(pc), 0)
        case "commit" :: h :: pc :: inst :: Nil => Commit(h.toInt, hex(pc), hex(inst))
        case "trap" :: h :: i :: c :: Nil => Trap(h.toInt, bool(i), c.toInt)
        case "trap" :: h :: i :: c :: epc :: tval :: Nil => TrapFields(h.toInt, bool(i), c.toInt, hex(epc), hex(tval))
        case "rf" :: "w" :: h :: k :: a :: d :: Nil => WriteRf(h.toInt, k.toInt, a.toInt, bytes(d, if (k == "1") 16 else 8))
        case "rf" :: "r" :: h :: k :: a :: d :: Nil => ReadRf(h.toInt, k.toInt, a.toInt, bytes(d, 8))
        case "vrf" :: "w" :: h :: r :: m :: d :: Nil => WriteVrf(h.toInt, r.toInt, mask(m, d.length / 2), bytes(d, d.length / 2))
        case "vs" :: h :: v :: Nil => WriteVs(h.toInt, v.toInt)
        case "policy" :: h :: kv => Policy(h.toInt, kv.mkString(" "))
        case "load" :: "exe" :: h :: id :: len :: a :: d :: Nil => LoadExe(h.toInt, id.toLong, len.toLong, hex(a), bytes(d, len.toInt))
        case "load" :: "com" :: h :: id :: Nil => LoadCom(h.toInt, id.toLong)
        case "load" :: "flu" :: h :: Nil => LoadFlush(h.toInt)
        case "store" :: "exe" :: h :: id :: len :: a :: d :: Nil => StoreExe(h.toInt, id.toLong, len.toLong, hex(a), bytes(d, len.toInt), None)
        case "store" :: "exe" :: h :: id :: len :: a :: d :: m :: Nil => StoreExe(h.toInt, id.toLong, len.toLong, hex(a), bytes(d, len.toInt), Some(mask(m, len.toInt)))
        case "store" :: "com" :: h :: id :: Nil => StoreCom(h.toInt, id.toLong)
        case "store" :: "bro" :: h :: id :: Nil => StoreBro(h.toInt, id.toLong)
        case "store" :: "sc" :: h :: f :: Nil => StoreSc(h.toInt, bool(f))
        case "io" :: h :: w :: a :: d :: m :: size :: err :: Nil => Io(h.toInt, bool(w), hex(a), bytes(d, size.toInt), hex(m).toInt, size.toInt, bool(err))
        case "int" :: "set" :: h :: id :: v :: Nil => SetInt(h.toInt, id.toInt, bool(v))
        case _ => throw new IllegalArgumentException(line)
      })
      case _ => throw new IllegalArgumentException(line)
    }
  }

  // (line number, event); comments and blank lines are skipped.
  def parse(f: File): Seq[(Int, Event)] = {
    val src = Source.fromFile(f)
    try src.getLines().zipWithIndex.flatMap { case (l, i) => parseLine(l).map(i + 1 -> _) }.toVector
    finally src.close()
  }

  def main(args: Array[String]): Unit = args.toList match {
    case "roundtrip" :: in :: out :: Nil =>
      val events = parse(new File(in))
      val backend = new FileBackend(new File(out))
      events.foreach(_._2.drive(backend))
      backend.close()
      val back = parse(new File(out)).map(_._2)
      val firstDiff = events.map(_._2).zipAll(back, null, null).indexWhere { case (a, b) => a != b }
      if (firstDiff >= 0) {
        val line = if (firstDiff < events.size) events(firstDiff)._1 else -1
        println(s"ROUNDTRIP FAIL line $line: ${events.lift(firstDiff).map(_._2)} != ${back.lift(firstDiff)}")
        sys.exit(1)
      }
      println(s"ROUNDTRIP OK ${events.size} events")
    case "jni" :: in :: workspace :: Nil =>
      val events = parse(new File(in))
      val backend = new RvlsBackend(new File(workspace))
      var line = 0
      try {
        events.foreach { case (l, e) => line = l; e.drive(backend) }
        println("JNI PASS")
      } catch {
        case e: Exception =>
          println(s"JNI FAIL line $line: ${e.getMessage}")
          sys.exit(1)
      }
    case _ =>
      System.err.println("usage: TraceReplay roundtrip <in.trace> <out.trace> | jni <in.trace> <workspace>")
      sys.exit(2)
  }
}
