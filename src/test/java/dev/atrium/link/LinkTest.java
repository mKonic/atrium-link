package dev.atrium.link;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;

// The same cases and golden bytes as atrium's tests/phonelink_test.cpp, on a
// plain JVM: `./build.sh test`.
public final class LinkTest {
    private static int failures;

    private static void check(boolean ok, String what) {
        if (!ok) {
            failures++;
            System.out.println("FAIL: " + what);
        }
    }

    private static void eq(Object got, Object want, String what) {
        check(String.valueOf(got).equals(String.valueOf(want)), what + ": got " + got + ", want " + want);
    }

    private static final HexFormat HEX = HexFormat.of();

    private static String hex(byte[] b) {
        return HEX.formatHex(b);
    }

    private static byte[] unhex(String s) {
        return HEX.parseHex(s);
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static void knownAnswers() {
        eq(hex(Crypto.hmac(ascii("Jefe"), ascii("what do ya want for nothing?"))),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "RFC 4231");
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        eq(hex(Crypto.hkdf(ikm, unhex("000102030405060708090a0b0c"), unhex("f0f1f2f3f4f5f6f7f8f9"), 42)),
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", "RFC 5869");
        byte[] alice = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bob = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        eq(hex(Crypto.x25519Public(alice)), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "RFC 7748 public");
        eq(hex(Crypto.x25519(alice, Crypto.x25519Public(bob))),
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "RFC 7748 shared");
        check(Crypto.x25519(alice, new byte[32]) == null, "low-order point refused");
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++)
            key[i] = (byte) i;
        eq(hex(Crypto.seal(key, Crypto.nonce(3, 7), ascii("hdr"), ascii("atrium"))),
                "c2f9205df6b4b89af3a5ad4667a19cbe3ab32b87170d", "AES-GCM");
        eq(hex(Crypto.seal(key, Crypto.nonce(1, 0), new byte[0], new byte[0])), "197b1d24ed7acc2678859df922c3b5cb",
                "AES-GCM empty");
        byte[] sealed = unhex("c2f9205df6b4b89af3a5ad4667a19cbe3ab32b87170d");
        eq(new String(Crypto.open(key, Crypto.nonce(3, 7), ascii("hdr"), sealed), StandardCharsets.UTF_8), "atrium", "open");
        check(Crypto.open(key, Crypto.nonce(3, 8), ascii("hdr"), sealed) == null, "wrong nonce fails");
        check(Crypto.open(key, Crypto.nonce(3, 7), ascii("hdR"), sealed) == null, "wrong aad fails");
    }

    // Deterministic "random": a counter's bytes, different per end.
    static Link.Random counting(int base) {
        int[] n = {0};
        return size -> {
            byte[] b = new byte[size];
            for (int i = 0; i < size; i++)
                b[i] = (byte) (base + n[0]++);
            return b;
        };
    }

    static final byte[] PC_ID = ascii("PPPPPPPPPPPPPPPP"), PHONE_ID = ascii("FFFFFFFFFFFFFFFF");

    static final class End {
        final Map<String, byte[]> keys = new HashMap<>();
        Link link;
        ByteArrayOutputStream outbox = new ByteArrayOutputStream();
        String code = "", closed = "";
        List<String> messages = new ArrayList<>();
        boolean ready;

        End(int role, byte[] id, String name, int base) {
            link = new Link(role, id, name, peer -> keys.get(hex(peer)), counting(base));
        }

        void apply(List<Link.Event> events) {
            for (Link.Event e : events) {
                switch (e.kind) {
                    case Link.Event.SEND: outbox.write(e.bytes, 0, e.bytes.length); break;
                    case Link.Event.PAIR_CODE: code = e.text; break;
                    case Link.Event.PAIRED: keys.put(hex(link.peerId()), e.bytes); break;
                    case Link.Event.READY: ready = true; break;
                    case Link.Event.MESSAGE: messages.add(e.type + ":" + new String(e.bytes, StandardCharsets.ISO_8859_1)); break;
                    case Link.Event.CLOSE: closed = e.text; break;
                    default:
                }
            }
        }

        byte[] take() {
            byte[] b = outbox.toByteArray();
            outbox.reset();
            return b;
        }

        void feed(byte[] b) {
            if (b.length > 0 && closed.isEmpty())
                apply(link.received(b, 0, b.length));
        }
    }

    static final class Pair {
        End pc = new End(Link.ROLE_PC, PC_ID, "desk", 1);
        End phone = new End(Link.ROLE_PHONE, PHONE_ID, "NX789J", 101);

        void pump() {
            for (int i = 0; i < 100 && (pc.outbox.size() > 0 || phone.outbox.size() > 0); i++) {
                byte[] ab = pc.take(), ba = phone.take();
                phone.feed(ab);
                pc.feed(ba);
            }
        }

        void connect() {
            pc.apply(pc.link.start());
            phone.apply(phone.link.start());
            pump();
        }

        void knowEachOther(String pcKey, String phoneKey) {
            pc.keys.put(hex(PHONE_ID), ascii(pcKey));
            phone.keys.put(hex(PC_ID), ascii(phoneKey));
        }
    }

    static final String K = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";

    static void pairs() {
        Pair p = new Pair();
        p.pc.link.setPairing(true);
        p.phone.link.setPairing(true);
        p.connect();
        eq(p.pc.code, p.phone.code, "same code");
        // Golden, from Python's cryptography; atrium pins it too.
        eq(p.pc.code, "077564", "golden code");
        check(!p.pc.ready, "not ready before accepting");
        p.phone.apply(p.phone.link.accept());
        p.pump();
        check(p.pc.keys.isEmpty(), "one accept isn't enough");
        p.pc.apply(p.pc.link.accept());
        p.pump();
        check(Arrays.equals(p.pc.keys.get(hex(PHONE_ID)), p.phone.keys.get(hex(PC_ID))), "same key");
        check(p.pc.ready && p.phone.ready, "ready after pairing");
        eq(p.pc.link.peerName(), "NX789J", "peer name");
        check(Arrays.equals(p.pc.link.datagramKey(), p.phone.link.datagramKey()), "same datagram key");
        p.pc.apply(p.pc.link.message(Link.AUDIO_START, new byte[] {0x13, (byte) 0x88, 0, (byte) 0xf0}));
        p.pump();
        eq(p.phone.messages, List.of("16:\u0013\u0088\u0000ð"), "sealed message");
    }

    static void known() {
        Pair p = new Pair();
        p.knowEachOther(K, K);
        p.connect();
        check(p.pc.code.isEmpty() && p.pc.ready && p.phone.ready, "known peers skip pairing");
    }

    static void failures() {
        Pair wrong = new Pair();
        wrong.knowEachOther(K, K.replace('k', 'x'));
        wrong.connect();
        check(!wrong.pc.ready && !wrong.phone.ready && !wrong.pc.closed.isEmpty(), "wrong key refused");

        Pair forgot = new Pair();
        forgot.pc.keys.put(hex(PHONE_ID), ascii(K));
        forgot.connect();
        eq(forgot.pc.closed, "the other end doesn't know us", "phone forgot");
        eq(forgot.phone.closed, "an unknown PC", "phone forgot, phone side");

        Pair notAsked = new Pair();
        notAsked.phone.link.setPairing(true);
        notAsked.connect();
        eq(notAsked.pc.closed, "not paired", "PC not pairing");

        Pair refused = new Pair();
        refused.pc.link.setPairing(true);
        refused.connect();
        eq(refused.pc.closed, "the phone isn't pairing now", "phone not pairing");

        Pair rejected = new Pair();
        rejected.pc.link.setPairing(true);
        rejected.phone.link.setPairing(true);
        rejected.connect();
        rejected.pc.apply(rejected.pc.link.accept());
        rejected.phone.apply(rejected.phone.link.reject());
        rejected.pump();
        eq(rejected.pc.closed, "pairing rejected on the other end", "rejected");
        check(rejected.phone.keys.isEmpty(), "rejected: nothing stored");

        // A REVEAL that doesn't match the COMMIT.
        Pair mitm = new Pair();
        mitm.pc.link.setPairing(true);
        mitm.phone.link.setPairing(true);
        mitm.pc.apply(mitm.pc.link.start());
        mitm.phone.apply(mitm.phone.link.start());
        for (int i = 0; i < 10; i++) {
            byte[] ab = mitm.pc.take(), ba = mitm.phone.take();
            if (ab.length > 4 && ab[4] == Link.PAIR_REVEAL)
                ab[10] ^= 1;
            mitm.phone.feed(ab);
            mitm.pc.feed(ba);
        }
        eq(mitm.phone.closed, "the PC's key doesn't match its commitment", "commitment");
        check(mitm.phone.code.isEmpty(), "no code after a bad reveal");

        // Tampered and replayed frames.
        Pair t = new Pair();
        t.knowEachOther(K, K);
        t.connect();
        byte[] f = t.pc.link.message(Link.AUDIO_STOP, new byte[0]).get(0).bytes;
        t.phone.feed(f);
        eq(t.phone.messages.size(), 1, "first frame taken");
        t.phone.feed(f);
        eq(t.phone.closed, "a frame failed authentication", "replay refused");
        Pair u = new Pair();
        u.knowEachOther(K, K);
        u.connect();
        byte[] g = u.pc.link.message(Link.AUDIO_STOP, new byte[0]).get(0).bytes;
        g[g.length - 1] ^= 1;
        u.phone.feed(g);
        eq(u.phone.closed, "a frame failed authentication", "tamper refused");

        // One byte at a time.
        Pair s = new Pair();
        s.knowEachOther(K, K);
        s.pc.apply(s.pc.link.start());
        s.phone.apply(s.phone.link.start());
        for (int i = 0; i < 20; i++) {
            byte[] ab = s.pc.take(), ba = s.phone.take();
            for (byte b : ab)
                s.phone.feed(new byte[] {b});
            for (byte b : ba)
                s.pc.feed(new byte[] {b});
        }
        check(s.pc.ready && s.phone.ready, "frames split anywhere");
    }

    static void media() {
        // Golden; atrium pins the same bytes.
        eq(hex(Link.packMedia(Link.MEDIA_PAUSED, Link.CAN_PLAY, 1, 2, "t", "", "al", "x", ascii("ART"))),
                "0201000000010000000200017400000002616c000178415254", "golden media");
        long[] cmd = Link.unpackMediaCommand(Crypto.unhex("0700011170"));
        check(cmd != null && cmd[0] == Link.CMD_SEEK && cmd[1] == 70000, "golden media command");
        check(Link.unpackMediaCommand(Crypto.unhex("0800000000")) == null, "unknown command");
        check(Link.unpackMediaCommand(Crypto.unhex("01")) == null, "short command");
    }

    static void datagrams() {
        Cipher c = Crypto.cipher();
        byte[] key = ascii(K.replace('k', 'a'));
        // Golden, from Python's cryptography; atrium pins the same bytes.
        eq(hex(Link.packAudio(c, key, 0, 1, 2, ascii("abcd"), 0, 1)),
                "a700000100000001000000021edb81fd9ad1b92580210f28316e1da2e88bc4f5", "golden audio");
        byte[] nack = Link.packNack(c, key, 9, new int[] {1, 5});
        eq(hex(nack), "a800000200000009b156f015fa5daa2ffe650a6aac7c4c23b7a068e6c4e009bb", "golden nack");
        long[] counter = new long[1];
        int[] seqs = Link.unpackNack(c, key, nack, nack.length, counter);
        check(seqs != null && Arrays.equals(seqs, new int[] {1, 5}) && counter[0] == 9, "nack round trip");
        byte[] wide = Link.packNack(c, key, 1, new int[] {-1});
        check(Arrays.equals(Link.unpackNack(c, key, wide, wide.length, null), new int[] {-1}), "seq 0xffffffff");
        nack[1] = 1;
        check(Link.unpackNack(c, key, nack, nack.length, null) == null, "nack header authenticated");
        eq(hex(Link.packAudio(Link.MIC, c, key, 0, 1, 2, ascii("abcd"), 0, 2)),
                "a900000200000001000000024b8c8aef3e11a4fb30b95f6fc68241c69937959d", "golden microphone");
        byte[] micNack = Link.packNack(Link.MIC, c, key, 9, new int[] {1, 5});
        eq(hex(micNack), "aa000002000000095509529152c1d64c4b82dc2d8de8ad5d0476ea78ae9d63a2", "golden microphone nack");
        check(Link.unpackNack(c, key, micNack, micNack.length, null) == null, "a microphone nack is no sound nack");
        check(Arrays.equals(Link.unpackNack(Link.MIC, c, key, micNack, micNack.length, null), new int[] {1, 5}),
                "microphone nack round trip");
        byte[] audio = Link.packAudio(c, key, 0, 1, 2, ascii("abcd"), 0, 1);
        check(Link.unpackNack(c, key, audio, audio.length, null) == null, "audio is no nack");
        byte[] full = Link.packAudio(c, key, Link.DISCONTINUITY, -2, 123456, new byte[960], 0, Link.PACKET_FRAMES);
        eq(full.length, Link.AUDIO_HEADER + 960 + Crypto.TAG, "packet size");
        check(full.length + 28 <= 1500, "one Ethernet frame");
    }

    public static void main(String[] args) {
        knownAnswers();
        pairs();
        known();
        failures();
        datagrams();
        media();
        if (failures > 0) {
            System.out.println(failures + " failed");
            System.exit(1);
        }
        System.out.println("link: all passed");
    }
}
