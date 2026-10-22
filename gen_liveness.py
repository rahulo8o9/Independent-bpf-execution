import argparse
import os
import random
import re
import struct
import subprocess
import sys

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
NSLOT = 8
KEY_OFF = -72
VAL_OFF = -80
BUF_OFF = -88
MAP_ENTRIES = 4
CB_BASE = 48
CTX_OFFS = [0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44]

ALU_CODE = {"ADD": 0x00, "SUB": 0x10, "MUL": 0x20, "DIV": 0x30, "OR": 0x40, "AND": 0x50,
            "LSH": 0x60, "RSH": 0x70, "NEG": 0x80, "MOD": 0x90, "XOR": 0xa0, "MOV": 0xb0,
            "ARSH": 0xc0}
BIN_OPS = ["ADD", "SUB", "MUL", "DIV", "MOD", "OR", "AND", "XOR", "LSH", "RSH", "ARSH"]
JMP_CODE = {"JEQ": 0x10, "JGT": 0x20, "JGE": 0x30, "JSET": 0x40, "JNE": 0x50, "JSGT": 0x60,
            "JSGE": 0x70, "JLT": 0xa0, "JLE": 0xb0, "JSLT": 0xc0, "JSLE": 0xd0}
SIZE_BITS = {4: 0x00, 2: 0x08, 1: 0x10, 8: 0x18}
ATOMIC_CODE = {"ADD": 0x00, "OR": 0x40, "AND": 0x50, "XOR": 0xa0}
HELPERS = {1: ("bpf_map_lookup_elem", 2), 2: ("bpf_map_update_elem", 4),
           3: ("bpf_map_delete_elem", 2), 5: ("bpf_ktime_get_ns", 0),
           7: ("bpf_get_prandom_u32", 0), 8: ("bpf_get_smp_processor_id", 0),
           26: ("bpf_skb_load_bytes", 4)}
LIVE_LINE = re.compile(r"^\s*(?:\d+\s+)?(\d+): ([.\d]{10}) \(")


class Insn:
    def __init__(self, kind, **kw):
        self.kind = kind
        self.width = 64
        self.op = None
        self.dst = None
        self.src = None
        self.imm = 0
        self.size = 8
        self.base = None
        self.off = 0
        self.target = None
        self.hid = 0
        self.fetch = False
        self.be = False
        self.bswap = False
        self.bits = 64
        self.soff = 0
        self.sx = False
        self.wide = False
        self.__dict__.update(kw)

    def slots(self):
        return 2 if self.kind in ("ldimm64", "ldmap") else 1

    def uses(self):
        k = self.kind
        u = set()
        if k == "alu":
            if self.op != "MOV":
                u.add(self.dst)
            if self.src is not None:
                u.add(self.src)
        elif k == "end":
            u.add(self.dst)
        elif k == "ldx":
            u.add(self.base)
        elif k == "st":
            u.add(self.base)
        elif k == "stx":
            u |= {self.base, self.src}
        elif k == "atomic":
            u |= {self.base, self.src}
            if self.op == "CMPXCHG":
                u.add(0)
        elif k == "jmp":
            u.add(self.dst)
            if self.src is not None:
                u.add(self.src)
        elif k == "call":
            u |= set(range(1, HELPERS[self.hid][1] + 1))
        elif k == "ldabs":
            u.add(6)
        elif k == "ldind":
            u |= {6, self.src}
        elif k == "exit":
            u.add(0)
        return {r for r in u if r < 10}

    def defs(self):
        k = self.kind
        d = set()
        if k in ("alu", "end", "ldimm64", "ldmap", "ldx"):
            d.add(self.dst)
        elif k == "atomic":
            if self.op == "CMPXCHG":
                d.add(0)
            elif self.op == "XCHG" or self.fetch:
                d.add(self.src)
        elif k in ("call", "ldabs", "ldind"):
            d |= set(range(6))
        return {r for r in d if r < 10}

    def encode(self, slot, slots, labels, idx):
        k = self.kind
        off = self.off
        if self.target is not None:
            off = slots[labels[self.target]] - (slot + 1)
        if k == "alu":
            cls = 7 if self.width == 64 else 4
            code = cls | ALU_CODE[self.op] | (0x08 if self.src is not None else 0)
            if self.op == "NEG":
                return pk(code, self.dst, 0, 0, 0)
            if self.src is not None:
                return pk(code, self.dst, self.src, self.soff, 0)
            return pk(code, self.dst, 0, self.soff, self.imm)
        if k == "end":
            if self.bswap:
                return pk(0x07 | 0xd0, self.dst, 0, 0, self.bits)
            return pk(0x04 | 0xd0 | (0x08 if self.be else 0), self.dst, 0, 0, self.bits)
        if k == "ldimm64":
            lo = self.imm & M32
            hi = (self.imm >> 32) & M32
            return pk(0x18, self.dst, 0, 0, lo) + pk(0, 0, 0, 0, hi)
        if k == "ldmap":
            return pk(0x18, self.dst, 1, 0, 0) + pk(0, 0, 0, 0, 0)
        if k == "ldx":
            return pk(0x01 | (0x80 if self.sx else 0x60) | SIZE_BITS[self.size], self.dst, self.base, off, 0)
        if k == "st":
            return pk(0x02 | 0x60 | SIZE_BITS[self.size], self.base, 0, off, self.imm)
        if k == "stx":
            return pk(0x03 | 0x60 | SIZE_BITS[self.size], self.base, self.src, off, 0)
        if k == "atomic":
            if self.op == "CMPXCHG":
                imm = 0xf1
            elif self.op == "XCHG":
                imm = 0xe1
            else:
                imm = ATOMIC_CODE[self.op] | (1 if self.fetch else 0)
            return pk(0x03 | 0xc0 | SIZE_BITS[self.size], self.base, self.src, off, imm)
        if k == "jmp":
            cls = 5 if self.width == 64 else 6
            code = cls | JMP_CODE[self.op] | (0x08 if self.src is not None else 0)
            if self.src is not None:
                return pk(code, self.dst, self.src, off, 0)
            return pk(code, self.dst, 0, off, self.imm)
        if k == "ja":
            if self.wide:
                return pk(0x06, 0, 0, 0, off)
            return pk(0x05, 0, 0, off, 0)
        if k == "call":
            return pk(0x85, 0, 0, 0, self.hid)
        if k == "ldabs":
            return pk(0x20 | SIZE_BITS[self.size], 0, 0, 0, self.imm)
        if k == "ldind":
            return pk(0x40 | SIZE_BITS[self.size], 0, self.src, 0, self.imm)
        return pk(0x95, 0, 0, 0, 0)

    def text(self):
        k = self.kind
        w = "r" if self.width == 64 else "w"
        if k == "alu":
            d = "%s%d" % (w, self.dst)
            s = "%s%d" % (w, self.src) if self.src is not None else str(self.imm)
            if self.op == "MOV":
                if self.soff:
                    return "%s = (s%d)%s" % (d, self.soff, s)
                return "%s = %s" % (d, s)
            if self.op == "NEG":
                return "%s = -%s" % (d, d)
            sym = {"ADD": "+=", "SUB": "-=", "MUL": "*=", "DIV": "/=", "MOD": "%=", "OR": "|=",
                   "AND": "&=", "XOR": "^=", "LSH": "<<=", "RSH": ">>=", "ARSH": "s>>="}[self.op]
            if self.soff == 1:
                sym = "s" + sym
            return "%s %s %s" % (d, sym, s)
        if k == "end":
            m = "bswap" if self.bswap else "be" if self.be else "le"
            return "r%d = %s%d r%d" % (self.dst, m, self.bits, self.dst)
        if k == "ldimm64":
            return "r%d = 0x%x ll" % (self.dst, self.imm & M64)
        if k == "ldmap":
            return "r%d = map" % self.dst
        reg = lambda r: "r%d" % r
        mem = lambda b, o, s: "*(u%d *)(r%d %+d)" % (s * 8, b, o)
        if k == "ldx":
            return "r%d = %s" % (self.dst, mem(self.base, self.off, self.size).replace("(u", "(s" if self.sx else "(u"))
        if k == "st":
            return "%s = %d" % (mem(self.base, self.off, self.size), self.imm)
        if k == "stx":
            return "%s = r%d" % (mem(self.base, self.off, self.size), self.src)
        if k == "atomic":
            f = "fetch_" if self.fetch or self.op in ("XCHG", "CMPXCHG") else ""
            return "atomic_%s%s(%s, r%d)" % (f, self.op.lower(), mem(self.base, self.off, self.size), self.src)
        if k == "jmp":
            s = "r%d" % self.src if self.src is not None else str(self.imm)
            return "if %s%d %s %s goto %s" % (w, self.dst, self.op, s, self.target)
        if k == "ja":
            return ("gotol %s" if self.wide else "goto %s") % self.target
        if k == "call":
            return "call %s#%d" % (HELPERS[self.hid][0], self.hid)
        if k == "ldabs":
            return "r0 = *(u%d *)skb[%d]" % (self.size * 8, self.imm)
        if k == "ldind":
            return "r0 = *(u%d *)skb[r%d + %d]" % (self.size * 8, self.src, self.imm)
        return "exit"


def pk(code, dst, src, off, imm):
    imm = ((imm + (1 << 31)) % (1 << 32)) - (1 << 31)
    return struct.pack("<BBhi", code, (src << 4) | dst, off, imm)


def mov_i(d, v, w=64):
    return Insn("alu", op="MOV", dst=d, imm=v, width=w)


def mov_r(d, s, w=64):
    return Insn("alu", op="MOV", dst=d, src=s, width=w)


def alu_i(op, d, v, w=64):
    return Insn("alu", op=op, dst=d, imm=v, width=w)


def alu_r(op, d, s, w=64):
    return Insn("alu", op=op, dst=d, src=s, width=w)


class State:
    def __init__(self):
        self.t = ["U"] * 10
        self.tt = [False] * 10
        self.si = [False] * NSLOT
        self.stt = [False] * NSLOT
        self.ci = [False] * 5

    def copy(self):
        n = State()
        n.assign(self)
        return n

    def assign(self, o):
        self.t = o.t[:]
        self.tt = o.tt[:]
        self.si = o.si[:]
        self.stt = o.stt[:]
        self.ci = o.ci[:]


def merge(a, b):
    n = State()
    for r in range(10):
        n.t[r] = a.t[r] if a.t[r] == b.t[r] else "U"
        n.tt[r] = a.tt[r] or b.tt[r]
    for i in range(NSLOT):
        n.si[i] = a.si[i] and b.si[i]
        n.stt[i] = a.stt[i] or b.stt[i]
    for i in range(5):
        n.ci[i] = a.ci[i] and b.ci[i]
    return n


class Env:
    def __init__(self, ctx, skb_len):
        self.ctx = ctx
        self.skb_len = skb_len
        self.fields = sorted(o for o in ctx)


class Gen:
    def __init__(self, rng, o, env):
        self.rng = rng
        self.o = o
        self.env = env
        self.n = 0

    def label(self):
        self.n += 1
        return "L%d" % self.n

    def imm(self):
        r = self.rng
        x = r.random()
        if x < 0.4:
            return r.randint(-16, 64)
        if x < 0.6:
            return r.choice([0x7fffffff, -0x80000000, 0xff, 0xffff, 0x7f, 0x80, -1, 1 << 16, 0x55aa55aa])
        return r.randint(-0x80000000, 0x7fffffff)

    def wregs(self, res, excl=()):
        return [r for r in (0, 1, 2, 3, 4, 5, 7, 8, 9) if r not in res and r not in excl]

    def sregs(self, st, untainted, excl=()):
        return [r for r in range(10) if st.t[r] == "S" and r not in excl and not (untainted and st.tt[r])]

    def need(self, st, out, res, excl=()):
        c = self.sregs(st, True, excl)
        if c:
            return self.rng.choice(c)
        d = self.rng.choice(self.wregs(res, excl))
        out.append(mov_i(d, self.imm()))
        st.t[d] = "S"
        st.tt[d] = False
        return d

    def clobber(self, st):
        for r in range(1, 6):
            st.t[r] = "U"
            st.tt[r] = False

    def count(self, out):
        return sum(1 for x in out if not isinstance(x, str))

    def producer(self, st, d):
        r = self.rng
        x = r.random()
        if x < 0.25:
            i = Insn("ldimm64", dst=d, imm=r.getrandbits(64))
        elif x < 0.4 and self.env.fields:
            i = Insn("ldx", dst=d, base=6, off=r.choice(self.env.fields), size=4)
        else:
            i = mov_i(d, self.imm(), r.choice((64, 32)))
        st.t[d] = "S"
        st.tt[d] = False
        return i

    def k_alu(self, st, res, restricted):
        r = self.rng
        w = r.choice((64, 32))
        x = r.random()
        if x < 0.12:
            c = [d for d in self.wregs(res) if st.t[d] == "S"]
            if not c:
                return None
            d = r.choice(c)
            if r.random() < 0.3:
                return [Insn("alu", op="NEG", dst=d, width=w)]
            m = r.choice(("le", "be", "bswap"))
            return [Insn("end", dst=d, bits=r.choice((16, 32, 64)), be=m == "be", bswap=m == "bswap")]
        if x < 0.30:
            d = r.choice(self.wregs(res))
            srcs = self.sregs(st, restricted)
            if srcs and r.random() < 0.5:
                s = r.choice(srcs)
                i = mov_r(d, s, w)
                if r.random() < 0.3:
                    i.soff = r.choice((8, 16, 32) if w == 64 else (8, 16))
                st.tt[d] = st.tt[s]
            else:
                i = mov_i(d, self.imm(), w)
                st.tt[d] = False
            st.t[d] = "S"
            return [i]
        c = [d for d in self.wregs(res) if st.t[d] == "S"]
        if not c:
            return None
        d = r.choice(c)
        op = r.choice(BIN_OPS)
        srcs = self.sregs(st, restricted)
        if srcs and r.random() < 0.5:
            s = r.choice(srcs)
            i = alu_r(op, d, s, w)
            st.tt[d] = st.tt[d] or st.tt[s]
        else:
            v = self.imm()
            if op in ("LSH", "RSH", "ARSH"):
                v = r.randrange(0, w)
            if op in ("DIV", "MOD") and v == 0:
                v = 3
            i = alu_i(op, d, v, w)
        if op in ("DIV", "MOD") and r.random() < 0.4:
            i.soff = 1
        return [i]

    def k_movi(self, st, res, restricted):
        return [self.producer(st, self.rng.choice(self.wregs(res)))]

    def k_ctx(self, st, res, restricted):
        if not self.env.fields:
            return None
        d = self.rng.choice(self.wregs(res))
        st.t[d] = "S"
        st.tt[d] = False
        return [Insn("ldx", dst=d, base=6, off=self.rng.choice(self.env.fields), size=4)]

    def slot_off(self, slot, size):
        return -8 * (slot + 1) + self.rng.randrange(0, 8, size)

    def k_stkst(self, st, res, restricted):
        r = self.rng
        slot = r.randrange(NSLOT)
        size = r.choice((1, 2, 4, 8))
        off = self.slot_off(slot, size)
        if r.random() < 0.4:
            i = Insn("st", size=size, base=10, off=off, imm=self.imm())
            t = False
        else:
            c = self.sregs(st, restricted)
            if not c:
                return None
            s = r.choice(c)
            i = Insn("stx", size=size, base=10, src=s, off=off)
            t = st.tt[s]
        if size == 8:
            st.si[slot] = True
            st.stt[slot] = t
        else:
            st.stt[slot] = st.stt[slot] or t
        return [i]

    def k_stkld(self, st, res, restricted):
        c = [i for i in range(NSLOT) if st.si[i] and not (restricted and st.stt[i])]
        if not c:
            return None
        slot = self.rng.choice(c)
        size = self.rng.choice((1, 2, 4, 8))
        d = self.rng.choice(self.wregs(res))
        st.t[d] = "S"
        st.tt[d] = st.stt[slot]
        return [Insn("ldx", dst=d, base=10, off=self.slot_off(slot, size), size=size,
                     sx=size < 8 and self.rng.random() < 0.3)]

    def k_cbst(self, st, res, restricted):
        c = self.sregs(st, True)
        if not c:
            return None
        i = self.rng.randrange(5)
        st.ci[i] = True
        return [Insn("stx", size=4, base=6, src=self.rng.choice(c), off=CB_BASE + 4 * i)]

    def k_cbld(self, st, res, restricted):
        c = [i for i in range(5) if st.ci[i]]
        if not c:
            return None
        d = self.rng.choice(self.wregs(res))
        st.t[d] = "S"
        st.tt[d] = False
        return [Insn("ldx", dst=d, base=6, off=CB_BASE + 4 * self.rng.choice(c), size=4)]

    def atomic_insn(self, st, res, base, off, size, allow_cmpxchg):
        r = self.rng
        ops = ["ADD", "OR", "AND", "XOR", "XCHG"] + (["CMPXCHG"] if allow_cmpxchg else [])
        aop = r.choice(ops)
        if aop == "CMPXCHG" and not (st.t[0] == "S" and not st.tt[0]):
            aop = "ADD"
        excl = set(res) | {0, base}
        c = self.sregs(st, True, excl)
        if not c:
            return None
        s = r.choice(c)
        fetch = aop not in ("XCHG", "CMPXCHG") and r.random() < 0.5
        i = Insn("atomic", size=size, op=aop, base=base, src=s, off=off, fetch=fetch)
        if aop == "CMPXCHG":
            st.t[0] = "S"
            st.tt[0] = False
        elif aop == "XCHG" or fetch:
            st.t[s] = "S"
            st.tt[s] = False
        return i

    def k_atom(self, st, res, restricted):
        c = [i for i in range(NSLOT) if st.si[i] and not st.stt[i]]
        if not c:
            return None
        size = self.rng.choice((4, 8))
        i = self.atomic_insn(st, res, 10, self.slot_off(self.rng.choice(c), size), size, True)
        return [i] if i else None

    def simple(self, st, res, restricted):
        kinds = ["alu"] * 7 + ["movi", "movi", "ctx", "stkst", "stkst", "stkld", "stkld", "cbst", "cbld"]
        if self.o.atomics:
            kinds += ["atom", "atom"]
        for _ in range(30):
            out = getattr(self, "k_" + self.rng.choice(kinds))(st, res, restricted)
            if out:
                return out
        d = self.rng.choice(self.wregs(res))
        return [self.producer(st, d)]

    def key_setup(self, st, out, res):
        r = self.rng
        if r.random() < 0.5:
            out.append(Insn("st", size=4, base=10, off=KEY_OFF, imm=r.randint(0, 6)))
        else:
            s = self.need(st, out, res)
            t = r.choice((2, 3, 4, 5))
            out += [mov_r(t, s), alu_i("AND", t, 7), Insn("stx", size=4, base=10, src=t, off=KEY_OFF)]

    def map_body(self, st, res):
        r = self.rng
        out = []
        for _ in range(r.randint(1, 3)):
            x = r.random()
            size = r.choice((1, 2, 4, 8))
            off = r.randrange(0, 8, size)
            if x < 0.3:
                d = r.choice(self.wregs(res, (0,)))
                out.append(Insn("ldx", dst=d, base=0, off=off, size=size))
                st.t[d] = "S"
                st.tt[d] = False
            elif x < 0.5:
                s = self.need(st, out, res, (0,))
                out.append(Insn("stx", size=size, base=0, src=s, off=off))
            elif x < 0.65:
                out.append(Insn("st", size=size, base=0, off=off, imm=self.imm()))
            elif self.o.atomics:
                size = r.choice((4, 8))
                i = self.atomic_insn(st, res, 0, r.randrange(0, 8, size), size, False)
                if i:
                    out.append(i)
        if not out:
            out.append(Insn("st", size=8, base=0, off=0, imm=self.imm()))
        return out

    def g_lookup(self, st, res):
        r = self.rng
        out = []
        self.key_setup(st, out, res)
        out += [Insn("ldmap", dst=1), mov_r(2, 10), alu_i("ADD", 2, KEY_OFF), Insn("call", hid=1)]
        self.clobber(st)
        st.t[0] = "U"
        st.tt[0] = False
        sb = st.copy()
        body = self.map_body(sb, res)
        sb.t[0] = "U"
        sb.tt[0] = False
        if r.random() < 0.5:
            end = self.label()
            out += [Insn("jmp", op="JEQ", dst=0, imm=0, target=end)] + body + [end]
            st.assign(merge(st, sb))
        else:
            lb = self.label()
            out += [Insn("jmp", op="JNE", dst=0, imm=0, target=lb), mov_i(0, self.imm()), Insn("exit"), lb] + body
            st.assign(sb)
        return out

    def g_update(self, st, res):
        r = self.rng
        out = []
        self.key_setup(st, out, res)
        if r.random() < 0.5:
            out.append(Insn("st", size=8, base=10, off=VAL_OFF, imm=self.imm()))
        else:
            s = self.need(st, out, res)
            out.append(Insn("stx", size=8, base=10, src=s, off=VAL_OFF))
        out += [mov_r(2, 10), alu_i("ADD", 2, KEY_OFF), mov_r(3, 10), alu_i("ADD", 3, VAL_OFF),
                mov_i(4, r.choice((0, 0, 1, 2))), Insn("ldmap", dst=1), Insn("call", hid=2)]
        self.clobber(st)
        st.t[0] = "S"
        st.tt[0] = False
        return out

    def g_delete(self, st, res):
        out = []
        self.key_setup(st, out, res)
        out += [Insn("ldmap", dst=1), mov_r(2, 10), alu_i("ADD", 2, KEY_OFF), Insn("call", hid=3)]
        self.clobber(st)
        st.t[0] = "S"
        st.tt[0] = False
        return out

    def g_nd(self, st, res):
        out = [Insn("call", hid=self.rng.choice((5, 7, 8)))]
        self.clobber(st)
        st.t[0] = "S"
        st.tt[0] = True
        return out

    def g_lb(self, st, res):
        if self.env.skb_len < 24:
            return None
        r = self.rng
        out = [mov_r(1, 6), mov_i(2, r.randint(0, 16)), mov_r(3, 10), alu_i("ADD", 3, BUF_OFF),
               mov_i(4, r.choice((1, 2, 4, 8))), Insn("call", hid=26)]
        self.clobber(st)
        st.t[0] = "S"
        st.tt[0] = False
        return out

    def g_abs(self, st, res):
        if self.env.skb_len < 24:
            return None
        r = self.rng
        out = [Insn("ldabs", size=r.choice((1, 2, 4)), imm=r.randint(0, 16))]
        self.clobber(st)
        st.t[0] = "S"
        st.tt[0] = False
        return out

    def g_ind(self, st, res):
        if self.env.skb_len < 24:
            return None
        r = self.rng
        x = r.choice(self.wregs(res))
        out = [mov_i(x, r.randint(0, 6)), Insn("ldind", size=r.choice((1, 2, 4)), src=x, imm=r.randint(0, 6))]
        self.clobber(st)
        st.t[0] = "S"
        st.tt[0] = False
        if x >= 7:
            st.t[x] = "S"
            st.tt[x] = False
        return out

    def gadget(self, st, res):
        names = ["lookup", "lookup", "update", "delete", "nd", "lb"]
        if self.o.legacy:
            names += ["abs", "ind"]
        for _ in range(10):
            out = getattr(self, "g_" + self.rng.choice(names))(st, res)
            if out:
                return out
        return None

    def cond(self, st, out, res):
        r = self.rng
        a = self.need(st, out, res)
        w = r.choice((64, 32))
        op = r.choice(list(JMP_CODE))
        c = self.sregs(st, True)
        if c and r.random() < 0.4:
            return Insn("jmp", op=op, dst=a, src=r.choice(c), width=w)
        return Insn("jmp", op=op, dst=a, imm=self.imm(), width=w)

    def prep_exit(self, st, out):
        if st.t[0] == "S" and not st.tt[0]:
            return
        c = self.sregs(st, True)
        if c and self.rng.random() < 0.6:
            out.append(mov_r(0, self.rng.choice(c)))
        else:
            out.append(mov_i(0, self.imm()))

    def s_if(self, st, depth, budget, res, restricted, allow_exit):
        r = self.rng
        out = []
        j = self.cond(st, out, res)
        base = st.copy()
        sub = max(1, min(budget, r.randint(2, 8)))
        st_t = base.copy()
        t_items, t_term = self.block(st_t, depth + 1, sub, res, restricted, allow_exit)
        if r.random() < 0.5:
            end = self.label()
            j.target = end
            out += [j] + t_items + [end]
            st.assign(base if t_term else merge(base, st_t))
        else:
            el = self.label()
            end = self.label()
            j.target = el
            st_e = base.copy()
            e_items, e_term = self.block(st_e, depth + 1, sub, res, restricted, allow_exit and not t_term)
            out += [j] + t_items
            if not t_term:
                out.append(Insn("ja", target=end, wide=r.random() < 0.3))
            out += [el] + e_items + [end]
            if t_term:
                st.assign(st_e)
            elif e_term:
                st.assign(st_t)
            else:
                st.assign(merge(st_t, st_e))
        return out

    def s_loop(self, st, depth, budget, res):
        r = self.rng
        c = [x for x in (7, 8, 9) if x not in res]
        if not c:
            return None
        rc = r.choice(c)
        n = r.randint(2, 4 if depth else 5)
        out = [mov_i(rc, 0)]
        st.t[rc] = "S"
        st.tt[rc] = False
        top = self.label()
        body, _ = self.block(st, depth + 1, max(1, min(budget, r.randint(2, 8))), res | {rc}, True, False)
        out += [top] + body + [alu_i("ADD", rc, 1), Insn("jmp", op="JLT", dst=rc, imm=n, target=top)]
        return out

    def block(self, st, depth, budget, res, restricted, allow_exit):
        out = []
        term = False
        first = True
        while not term and (first or self.count(out) < budget):
            names = ["simple"]
            weights = [55]
            if self.o.branches and depth < self.o.depth and not first:
                names.append("if")
                weights.append(14)
            if self.o.loops and depth < self.o.depth and not first and len(res) < 3:
                names.append("loop")
                weights.append(5)
            if not restricted and self.o.helpers and not first:
                names.append("gadget")
                weights.append(12)
            if allow_exit and depth > 0 and not first:
                names.append("exit")
                weights.append(4)
            k = self.rng.choices(names, weights)[0]
            first = False
            if k == "if":
                out += self.s_if(st, depth, budget - self.count(out), res, restricted, allow_exit)
            elif k == "loop":
                x = self.s_loop(st, depth, budget - self.count(out), res)
                out += x if x else self.simple(st, res, restricted)
            elif k == "gadget":
                x = self.gadget(st, res)
                out += x if x else self.simple(st, res, restricted)
            elif k == "exit":
                tmp = st.copy()
                self.prep_exit(tmp, out)
                out.append(Insn("exit"))
                term = True
            else:
                out += self.simple(st, res, restricted)
        return out, term

    def program(self):
        st = State()
        out = [mov_r(6, 1)]
        st.t[6] = "C"
        for d in self.rng.sample([0, 1, 2, 3, 4, 5, 7, 8, 9], self.rng.randint(2, 6)):
            out.append(self.producer(st, d))
        body, _ = self.block(st, 0, self.o.size, set(), False, False)
        out += body
        self.prep_exit(st, out)
        out.append(Insn("exit"))
        return out


def assemble(items):
    insns = []
    labels = {}
    for it in items:
        if isinstance(it, str):
            labels[it] = len(insns)
        else:
            insns.append(it)
    slots = []
    s = 0
    for i in insns:
        slots.append(s)
        s += i.slots()
    return insns, labels, slots


def to_bytes(insns, labels, slots):
    return b"".join(i.encode(slots[n], slots, labels, n) for n, i in enumerate(insns))


def oracle(insns, labels):
    n = len(insns)
    succ = []
    for i, x in enumerate(insns):
        if x.kind == "exit":
            succ.append([])
        elif x.kind == "ja":
            succ.append([labels[x.target]])
        elif x.kind == "jmp":
            succ.append([i + 1, labels[x.target]])
        else:
            succ.append([i + 1])
    live = [set() for _ in range(n)]
    changed = True
    while changed:
        changed = False
        for i in range(n - 1, -1, -1):
            out = set()
            for s in succ[i]:
                out |= live[s]
            new = insns[i].uses() | (out - insns[i].defs())
            if new != live[i]:
                live[i] = new
                changed = True
    return live


class Bug(Exception):
    pass


class SP:
    def __init__(self, off):
        self.off = off


class MP:
    def __init__(self, key):
        self.key = key


CTX = "ctx"


def sgn(v, w):
    v &= (1 << w) - 1
    return v - (1 << w) if v >> (w - 1) else v


def sdivmod(op, a, b, w):
    m = (1 << w) - 1
    sa, sb = sgn(a, w), sgn(b, w)
    if sb == 0:
        return 0 if op == "DIV" else a & m
    q = abs(sa) // abs(sb)
    if (sa < 0) != (sb < 0):
        q = -q
    return (q if op == "DIV" else sa - q * sb) & m


def alu(op, a, b, w, soff=0):
    m = (1 << w) - 1
    a &= m
    b &= m
    if soff == 1 and op in ("DIV", "MOD"):
        return sdivmod(op, a, b, w)
    if op == "ADD":
        r = a + b
    elif op == "SUB":
        r = a - b
    elif op == "MUL":
        r = a * b
    elif op == "DIV":
        r = a // b if b else 0
    elif op == "MOD":
        r = a % b if b else a
    elif op == "OR":
        r = a | b
    elif op == "AND":
        r = a & b
    elif op == "XOR":
        r = a ^ b
    elif op == "LSH":
        r = a << (b & (w - 1))
    elif op == "RSH":
        r = a >> (b & (w - 1))
    elif op == "ARSH":
        r = sgn(a, w) >> (b & (w - 1))
    elif op == "NEG":
        r = -a
    else:
        r = b
    return r & m


def cond(op, a, b, w):
    m = (1 << w) - 1
    a &= m
    b &= m
    sa, sb = sgn(a, w), sgn(b, w)
    return {"JEQ": a == b, "JNE": a != b, "JGT": a > b, "JGE": a >= b, "JLT": a < b,
            "JLE": a <= b, "JSGT": sa > sb, "JSGE": sa >= sb, "JSLT": sa < sb,
            "JSLE": sa <= sb, "JSET": (a & b) != 0}[op]


def execute(insns, labels, env, ndseed):
    rng = random.Random(ndseed)
    regs = [None] * 11
    regs[1] = CTX
    regs[10] = SP(0)
    stack = bytearray(512)
    cb = bytearray(20)
    maps = {k: bytearray(8) for k in range(MAP_ENTRIES)}

    def get(r):
        v = regs[r]
        if v is None:
            raise Bug("uninitialized r%d" % r)
        return v

    def geti(r):
        v = get(r)
        if not isinstance(v, int):
            raise Bug("pointer used as scalar r%d" % r)
        return v

    def loc(base, off, size):
        if isinstance(base, SP):
            mem, a = stack, 512 + base.off + off
        elif isinstance(base, MP):
            mem, a = maps[base.key], off
        elif base == CTX:
            mem, a = cb, off - CB_BASE
        else:
            raise Bug("bad base")
        if a < 0 or a + size > len(mem):
            raise Bug("out of range access")
        return mem, a

    def load(base, off, size):
        if base == CTX and not (CB_BASE <= off < CB_BASE + 20):
            return env.ctx[off]
        mem, a = loc(base, off, size)
        return int.from_bytes(mem[a:a + size], "little")

    def store(base, off, size, v):
        mem, a = loc(base, off, size)
        mem[a:a + size] = (v & ((1 << (size * 8)) - 1)).to_bytes(size, "little")

    pc = 0
    steps = 0
    while True:
        steps += 1
        if steps > 300000:
            raise Bug("step limit")
        i = insns[pc]
        k = i.kind
        nxt = pc + 1
        if k == "exit":
            return geti(0) & M32
        if k == "alu":
            if i.op == "MOV" and i.src is not None:
                v = get(i.src)
                if i.soff:
                    v = sgn(geti(i.src), i.soff) & ((1 << i.width) - 1)
                elif i.width == 32:
                    if not isinstance(v, int):
                        raise Bug("mov32 pointer")
                    v &= M32
                regs[i.dst] = v
            else:
                a = 0 if i.op == "MOV" else get(i.dst)
                if isinstance(a, SP):
                    if i.op != "ADD" or i.width != 64 or i.src is not None:
                        raise Bug("bad pointer arithmetic")
                    regs[i.dst] = SP(a.off + i.imm)
                else:
                    if i.src is not None:
                        b = geti(i.src)
                    else:
                        b = i.imm
                    regs[i.dst] = alu(i.op, a if isinstance(a, int) else 0, b, i.width, i.soff)
        elif k == "end":
            v = geti(i.dst) & ((1 << i.bits) - 1)
            if i.be or i.bswap:
                v = int.from_bytes(v.to_bytes(i.bits // 8, "little"), "big")
            regs[i.dst] = v
        elif k == "ldimm64":
            regs[i.dst] = i.imm & M64
        elif k == "ldmap":
            regs[i.dst] = "map"
        elif k == "ldx":
            v = load(get(i.base), i.off, i.size)
            regs[i.dst] = sgn(v, i.size * 8) & M64 if i.sx else v
        elif k == "st":
            store(get(i.base), i.off, i.size, i.imm)
        elif k == "stx":
            store(get(i.base), i.off, i.size, geti(i.src))
        elif k == "atomic":
            base = get(i.base)
            mask = (1 << (i.size * 8)) - 1
            old = load(base, i.off, i.size)
            if i.op == "CMPXCHG":
                if old == (geti(0) & mask):
                    store(base, i.off, i.size, geti(i.src))
                regs[0] = old
            elif i.op == "XCHG":
                v = geti(i.src) & mask
                store(base, i.off, i.size, v)
                regs[i.src] = old
            else:
                s = geti(i.src) & mask
                fn = {"ADD": lambda a, b: a + b, "OR": lambda a, b: a | b,
                      "AND": lambda a, b: a & b, "XOR": lambda a, b: a ^ b}[i.op]
                store(base, i.off, i.size, fn(old, s))
                if i.fetch:
                    regs[i.src] = old
        elif k == "jmp":
            a = get(i.dst)
            if isinstance(a, MP):
                a = 1
            if not isinstance(a, int):
                raise Bug("pointer compare")
            b = geti(i.src) if i.src is not None else i.imm
            if cond(i.op, a, b, i.width):
                nxt = labels[i.target]
        elif k == "ja":
            nxt = labels[i.target]
        elif k == "call":
            h = i.hid
            if h in (1, 2, 3):
                p = get(2)
                if not isinstance(p, SP):
                    raise Bug("key pointer")
                a = 512 + p.off
                key = int.from_bytes(stack[a:a + 4], "little")
            if h == 1:
                regs[0] = MP(key) if key < MAP_ENTRIES else 0
            elif h == 2:
                p = get(3)
                a = 512 + p.off
                val = bytes(stack[a:a + 8])
                flags = geti(4)
                if key >= MAP_ENTRIES:
                    regs[0] = (-7) & M64
                elif flags == 1:
                    regs[0] = (-17) & M64
                else:
                    maps[key][:] = val
                    regs[0] = 0
            elif h == 3:
                regs[0] = (-22) & M64
            elif h == 5:
                regs[0] = rng.getrandbits(64)
            elif h == 7:
                regs[0] = rng.getrandbits(32)
            elif h == 8:
                regs[0] = rng.randrange(8)
            elif h == 26:
                off = geti(2)
                ln = geti(4)
                p = get(3)
                if off + ln <= env.skb_len:
                    a = 512 + p.off
                    stack[a:a + ln] = bytes(ln)
                    regs[0] = 0
                else:
                    regs[0] = (-14) & M64
            for r in range(1, 6):
                regs[r] = None
        elif k in ("ldabs", "ldind"):
            off = i.imm if k == "ldabs" else geti(i.src) + i.imm
            if off < 0 or off + i.size > env.skb_len:
                return 0
            regs[0] = 0
            for r in range(1, 6):
                regs[r] = None
        pc = nxt


def listing(insns, labels, slots, exp):
    inv = {}
    for name, idx in labels.items():
        inv.setdefault(idx, []).append(name)
    lines = []
    for n, i in enumerate(insns):
        for name in inv.get(n, []):
            lines.append("%s:" % name)
        lines.append("  %3d  %-58s live-in %s" % (slots[n], i.text(), sorted(exp[n])))
    return "\n".join(lines) + "\n"


def run_runner(runner, path):
    p = subprocess.run([runner, path], capture_output=True, text=True, timeout=300)
    return p.stdout + p.stderr


def parse(out):
    live = {}
    for line in out.splitlines():
        m = LIVE_LINE.match(line)
        if m:
            live[int(m.group(1))] = {int(c) for c in m.group(2) if c != "."}
    rv = re.search(r"r0 \(retval\) = (\d+)", out)
    return live, (int(rv.group(1)) if rv else None)


def tiny(path, runner, items):
    insns, labels, slots = assemble(items)
    with open(path, "wb") as f:
        f.write(to_bytes(insns, labels, slots))
    return parse(run_runner(runner, path))[1]


def calibrate(runner, tmp):
    ctx = {}
    for off in CTX_OFFS:
        vals = []
        for _ in range(2):
            vals.append(tiny(tmp, runner, [mov_r(6, 1), Insn("ldx", dst=0, base=6, off=off, size=4), Insn("exit")]))
        if vals[0] is not None and vals[0] == vals[1]:
            ctx[off] = vals[0]
    return Env(ctx, ctx.get(0, 0))


def compare(insns, slots, exp, out, rv_expected):
    live, rv = parse(out)
    loaded = "failed to load prog" not in out
    miss = []
    extra = []
    for n, e in enumerate(exp):
        g = live.get(slots[n])
        if g is None:
            miss.append("insn %d (slot %d): no liveness line in verifier log" % (n, slots[n]))
            continue
        if e - g:
            miss.append("insn %d (slot %d) %s: oracle %s verifier %s missing %s" % (
                n, slots[n], insns[n].text(), sorted(e), sorted(g), sorted(e - g)))
        if g - e:
            extra.append("insn %d (slot %d) %s: oracle %s verifier %s extra %s" % (
                n, slots[n], insns[n].text(), sorted(e), sorted(g), sorted(g - e)))
    detail = "\n".join(miss + extra)
    if not loaded:
        tail = [l for l in out.split("--- END LOG ---")[0].splitlines() if l.strip()][-3:]
        return "LOAD_FAILED", "\n".join(tail) + ("\n" + detail if detail else "")
    if miss and extra:
        return "LIVENESS_BOTH", detail
    if miss:
        return "LIVENESS_UNDER", detail
    if extra:
        return "LIVENESS_OVER", detail
    if rv != rv_expected:
        return "RUNTIME_MISMATCH", "interpreter r0=%d verifier-accepted program returned r0=%s" % (rv_expected, rv)
    return "MATCH", ""


def build_runner(path, src):
    inc = os.path.expanduser("~/xdp-tutorial/lib/install/include")
    lib = os.path.expanduser("~/xdp-tutorial/lib/install/lib/libbpf.a")
    cmd = ["gcc", "-O2", "-I" + inc, "-o", path, src, lib, "-lelf", "-lz"]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.path.expanduser("~/Independent-bpf-execution"))
    ap.add_argument("--out", default=None)
    ap.add_argument("--count", type=int, default=50)
    ap.add_argument("--size", type=int, default=40)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--no-branches", dest="branches", action="store_false")
    ap.add_argument("--no-loops", dest="loops", action="store_false")
    ap.add_argument("--no-helpers", dest="helpers", action="store_false")
    ap.add_argument("--legacy", action="store_true")
    ap.add_argument("--keep-logs", action="store_true")
    ap.add_argument("--no-atomics", dest="atomics", action="store_false")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run with sudo")
    runner = os.path.join(a.repo, "bpf_runner")
    if not os.path.exists(runner):
        build_runner(runner, os.path.join(a.repo, "bpf_runner.c"))
    out_root = a.out or os.path.join(a.repo, "liveness_tests", "generated")
    os.makedirs(out_root, exist_ok=True)
    tmp = os.path.join(out_root, ".calib.bin")
    env = calibrate(runner, tmp)
    print("ctx fields:", env.ctx, "skb_len:", env.skb_len)
    counts = {}
    try:
        for n in range(a.count):
            seed = a.seed + n
            g = Gen(random.Random(seed), a, env)
            insns, labels, slots = assemble(g.program())
            exp = oracle(insns, labels)
            case = os.path.join(out_root, "%05d" % seed)
            os.makedirs(case, exist_ok=True)
            binp = os.path.join(case, "prog.bin")
            with open(binp, "wb") as f:
                f.write(to_bytes(insns, labels, slots))
            with open(os.path.join(case, "prog.txt"), "w") as f:
                f.write(listing(insns, labels, slots, exp))
            try:
                r1 = execute(insns, labels, env, 1)
                r2 = execute(insns, labels, env, 2)
                if r1 != r2:
                    raise Bug("result depends on nondeterministic helper")
            except Bug as e:
                status, detail = "GENERATOR_BUG", str(e)
                out = ""
            else:
                out = run_runner(runner, binp)
                status, detail = compare(insns, slots, exp, out, r1)
            if status != "MATCH" or a.keep_logs:
                with open(os.path.join(case, "output.txt"), "w") as f:
                    f.write(out)
            with open(os.path.join(case, "report.txt"), "w") as f:
                f.write("status: %s\nseed: %d\ninsns: %d\n%s\n" % (status, seed, len(insns), detail))
            os.rename(case, case + "_" + status)
            counts[status] = counts.get(status, 0) + 1
            print("%05d %-18s insns=%d" % (seed, status, len(insns)))
            if status not in ("MATCH",):
                print("    " + detail.replace("\n", "\n    "))
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
        st = os.stat(a.repo)
        subprocess.run(["chown", "-R", "%d:%d" % (st.st_uid, st.st_gid), out_root])
    print(counts)


if __name__ == "__main__":
    main()
