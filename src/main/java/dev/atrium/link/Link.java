package dev.atrium.link;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;

// The network link with atrium, the same rules as atrium's link_core.cpp
// (whose header documents the wire format); change one, change both. Fed
// bytes, answering with events; it never touches a socket. Both roles are
// here so the tests can run a PC against a phone.
public final class Link {
    public static final String SERVICE_TYPE = "_atrium-link._tcp";
    static final int VERSION = 1;
    static final int ID_SIZE = 16;
    static final int MAX_FRAME = 16 << 20;
    public static final int RATE = 48000, CHANNELS = 2, FRAME_BYTES = 4;
    public static final int PACKET_FRAMES = 240;  // 5 ms: 960 bytes, under the MTU

    public static final int ROLE_PC = 0, ROLE_PHONE = 1;

    public static final int HELLO = 1, PAIR_COMMIT = 2, PAIR_KEY = 3, PAIR_REVEAL = 4, PAIR_ACCEPT = 5,
            PAIR_REJECT = 6, AUTH = 7, PROOF = 8, UNKNOWN = 9, REFUSED = 10,
            AUDIO_START = 16, AUDIO_STOP = 17, AUDIO_STATE = 18, MEDIA = 19, MEDIA_COMMAND = 20,
            DISCONNECT = 21, WANT = 22, MIC_STATE = 23, MIC_START = 24, MIC_STOP = 25;

    public static final int AUDIO_STOPPED = 0, AUDIO_STREAMING = 1, AUDIO_FAILED = 2;
    // MIC_STATE: not shared; shared and closed; recording; shared, but it can't record.
    public static final int MIC_OFF = 0, MIC_READY = 1, MIC_LIVE = 2, MIC_FAILED = 3;

    public static final int MEDIA_NONE = 0, MEDIA_PLAYING = 1, MEDIA_PAUSED = 2, MEDIA_STOPPED = 3;
    public static final int CAN_PLAY = 1, CAN_PAUSE = 2, CAN_NEXT = 4, CAN_PREVIOUS = 8, CAN_SEEK = 16;
    public static final int CMD_PLAY = 1, CMD_PAUSE = 2, CMD_PLAY_PAUSE = 3, CMD_NEXT = 4, CMD_PREVIOUS = 5,
            CMD_STOP = 6, CMD_SEEK = 7;

    private static final byte[] PAIR_LABEL = "atrium-link pair v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PROOF_LABEL = "atrium-link proof v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SESSION_LABEL = "atrium-link session v1".getBytes(StandardCharsets.UTF_8);
    private static final int NONCE_SIZE = 16;
    private static final int PC_LABEL = 1, PHONE_LABEL = 2;

    public static final class Event {
        public static final int SEND = 0, PAIR_CODE = 1, PAIRED = 2, READY = 3, MESSAGE = 4, CLOSE = 5;
        public final int kind;
        public final byte[] bytes;
        public final String text;
        public final int type;

        Event(int kind, byte[] bytes, String text, int type) {
            this.kind = kind;
            this.bytes = bytes;
            this.text = text;
            this.type = type;
        }
    }

    public interface KeyLookup {
        byte[] key(byte[] peerId);  // null when there is none
    }

    public interface Random {
        byte[] bytes(int n);
    }

    private static final int PHASE_HELLO = 0, PHASE_PAIRING = 1, PHASE_CONFIRM = 2, PHASE_AUTH = 3,
            PHASE_READY = 4, PHASE_CLOSED = 5;

    private final int role;
    private final byte[] id;
    private final String name;
    private final KeyLookup keys;
    private final Random random;
    private boolean pairing;
    private int phase = PHASE_HELLO;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private byte[] peerId = new byte[0];
    private String peerName = "";

    private byte[] ownPriv, commit, pcPub, phonePub, secret, transcript;
    private boolean acceptedHere, acceptedThere;

    private byte[] key, pcNonce, phoneNonce;
    private boolean proofSent;
    private byte[] sendKey, recvKey, udp;
    private long sent, got;
    private final Cipher cipher = Crypto.cipher();

    public Link(int role, byte[] id, String name, KeyLookup keys, Random random) {
        this.role = role;
        this.id = id;
        this.name = name;
        this.keys = keys;
        this.random = random;
    }

    public void setPairing(boolean on) {
        pairing = on;
    }

    public boolean ready() {
        return phase == PHASE_READY;
    }

    public byte[] peerId() {
        return peerId;
    }

    public String peerName() {
        return peerName;
    }

    // The datagrams' key, once ready.
    public byte[] datagramKey() {
        return udp;
    }

    public List<Event> start() {
        List<Event> out = new ArrayList<>();
        send(HELLO, helloBody(role, id, name), out);
        return out;
    }

    static byte[] helloBody(int role, byte[] id, String name) {
        byte[] n = name.getBytes(StandardCharsets.UTF_8);
        byte[] b = new byte[3 + id.length + n.length];
        b[0] = (byte) (VERSION >> 8);
        b[1] = (byte) VERSION;
        b[2] = (byte) role;
        System.arraycopy(id, 0, b, 3, id.length);
        System.arraycopy(n, 0, b, 3 + id.length, n.length);
        return b;
    }

    static byte[] transcript(byte[] pcId, byte[] phoneId, byte[] pcPub, byte[] phonePub) {
        return Crypto.sha256(Crypto.cat(PAIR_LABEL, pcId, phoneId, pcPub, phonePub));
    }

    static String pairCode(byte[] transcript) {
        long v = get(transcript, 0, 4);
        return String.format("%06d", v % 1_000_000L);
    }

    static long get(byte[] s, int at, int bytes) {
        long v = 0;
        for (int i = 0; i < bytes; i++)
            v = v << 8 | (s[at + i] & 0xff);
        return v;
    }

    static void put32(byte[] b, int at, long v) {
        for (int i = 0; i < 4; i++)
            b[at + i] = (byte) (v >>> (24 - 8 * i));
    }

    private void send(int type, byte[] body, List<Event> out) {
        byte[] plain = new byte[1 + body.length];
        plain[0] = (byte) type;
        System.arraycopy(body, 0, plain, 1, body.length);
        byte[] frame;
        if (phase != PHASE_READY) {
            frame = new byte[4 + plain.length];
            put32(frame, 0, plain.length);
            System.arraycopy(plain, 0, frame, 4, plain.length);
        } else {
            byte[] len = new byte[4];
            put32(len, 0, plain.length + Crypto.TAG);
            int label = role == ROLE_PC ? PC_LABEL : PHONE_LABEL;
            frame = Crypto.cat(len, Crypto.seal(cipher, sendKey, Crypto.nonce(label, sent++), len, plain, 0, plain.length));
        }
        out.add(new Event(Event.SEND, frame, null, type));
    }

    private void close(String why, List<Event> out) {
        if (phase == PHASE_CLOSED)
            return;
        phase = PHASE_CLOSED;
        out.add(new Event(Event.CLOSE, null, why, 0));
    }

    public List<Event> received(byte[] bytes, int off, int len) {
        List<Event> out = new ArrayList<>();
        if (phase == PHASE_CLOSED)
            return out;
        buffer.write(bytes, off, len);
        byte[] buf = buffer.toByteArray();
        int at = 0;
        while (phase != PHASE_CLOSED && buf.length - at >= 4) {
            long n = get(buf, at, 4);
            if (n == 0 || n > MAX_FRAME) {
                close("bad frame", out);
                break;
            }
            if (buf.length - at < 4 + n)
                break;
            byte[] plain;
            if (phase == PHASE_READY) {
                int label = role == ROLE_PC ? PHONE_LABEL : PC_LABEL;
                plain = Crypto.open(cipher, recvKey, Crypto.nonce(label, got++), Arrays.copyOfRange(buf, at, at + 4),
                        buf, at + 4, (int) n);
                if (plain == null || plain.length == 0) {
                    close("a frame failed authentication", out);
                    break;
                }
            } else {
                plain = Arrays.copyOfRange(buf, at + 4, at + 4 + (int) n);
            }
            at += 4 + (int) n;
            handle(plain[0] & 0xff, Arrays.copyOfRange(plain, 1, plain.length), out);
        }
        buffer.reset();
        if (phase != PHASE_CLOSED)
            buffer.write(buf, at, buf.length - at);
        return out;
    }

    private void handle(int type, byte[] body, List<Event> out) {
        boolean pc = role == ROLE_PC;
        switch (phase) {
            case PHASE_HELLO: {
                if (type != HELLO || body.length < 3 + ID_SIZE) {
                    close("expected HELLO", out);
                    return;
                }
                if (get(body, 0, 2) != VERSION) {
                    close("version " + get(body, 0, 2) + " is not " + VERSION, out);
                    return;
                }
                if ((body[2] & 0xff) == role) {
                    close("the other end is the same kind", out);
                    return;
                }
                peerId = Arrays.copyOfRange(body, 3, 3 + ID_SIZE);
                peerName = new String(body, 3 + ID_SIZE, body.length - 3 - ID_SIZE, StandardCharsets.UTF_8);
                if (!pc) {
                    phase = PHASE_AUTH;  // or pairing, whichever the PC starts
                    return;
                }
                byte[] k = keys.key(peerId);
                if (k != null) {
                    key = k;
                    phase = PHASE_AUTH;
                    startAuth(out);
                } else if (pairing) {
                    phase = PHASE_PAIRING;
                    ownPriv = random.bytes(32);
                    pcPub = Crypto.x25519Public(ownPriv);
                    send(PAIR_COMMIT, Crypto.sha256(pcPub), out);
                } else {
                    close("not paired", out);
                }
                return;
            }
            case PHASE_PAIRING:
                if (!pc && type == PAIR_COMMIT && body.length == 32) {
                    commit = body;
                    ownPriv = random.bytes(32);
                    phonePub = Crypto.x25519Public(ownPriv);
                    send(PAIR_KEY, phonePub, out);
                    return;
                }
                if (pc && type == PAIR_KEY && body.length == 32) {
                    phonePub = body;
                    send(PAIR_REVEAL, pcPub, out);
                } else if (!pc && type == PAIR_REVEAL && body.length == 32) {
                    pcPub = body;
                    if (!Crypto.same(Crypto.sha256(pcPub), commit)) {
                        close("the PC's key doesn't match its commitment", out);
                        return;
                    }
                } else if (pc && type == REFUSED) {
                    close("the phone isn't pairing now", out);
                    return;
                } else {
                    close("unexpected message while pairing", out);
                    return;
                }
                secret = Crypto.x25519(ownPriv, pc ? phonePub : pcPub);
                if (secret == null) {
                    close("bad key", out);
                    return;
                }
                transcript = pc ? transcript(id, peerId, pcPub, phonePub) : transcript(peerId, id, pcPub, phonePub);
                phase = PHASE_CONFIRM;
                out.add(new Event(Event.PAIR_CODE, null, pairCode(transcript), 0));
                return;
            case PHASE_CONFIRM:
                if (type == PAIR_ACCEPT) {
                    acceptedThere = true;
                    if (acceptedHere)
                        pairDone(out);
                } else if (type == PAIR_REJECT) {
                    close("pairing rejected on the other end", out);
                } else {
                    close("unexpected message while confirming", out);
                }
                return;
            case PHASE_AUTH:
                if (!pc && type == PAIR_COMMIT) {
                    if (!pairing) {
                        send(REFUSED, new byte[0], out);
                        close("a pairing came while not pairing", out);
                        return;
                    }
                    phase = PHASE_PAIRING;
                    handle(type, body, out);
                    return;
                }
                if (type == UNKNOWN) {
                    close("the other end doesn't know us", out);
                    return;
                }
                if (type == AUTH && body.length == NONCE_SIZE) {
                    if (pc) {
                        if (phoneNonce != null) {
                            close("AUTH twice", out);
                            return;
                        }
                        phoneNonce = body;
                        return;  // its PROOF follows
                    }
                    // Just paired: the key is ours already, maybe not yet stored.
                    if (key == null) {
                        byte[] k = keys.key(peerId);
                        if (k == null) {
                            send(UNKNOWN, new byte[0], out);
                            close("an unknown PC", out);
                            return;
                        }
                        key = k;
                    }
                    pcNonce = body;
                    phoneNonce = random.bytes(NONCE_SIZE);
                    send(AUTH, phoneNonce, out);
                    sendProof(out);
                    return;
                }
                if (type == PROOF && phoneNonce != null && pcNonce != null) {
                    if (!Crypto.same(body, proof(pc ? ROLE_PHONE : ROLE_PC))) {
                        close("wrong proof: the other end has another key", out);
                        return;
                    }
                    if (!proofSent)
                        sendProof(out);
                    deriveSession();
                    phase = PHASE_READY;
                    out.add(new Event(Event.READY, null, null, 0));
                    return;
                }
                close("unexpected message while authenticating", out);
                return;
            case PHASE_READY:
                if (type < AUDIO_START) {
                    close("a handshake message after the handshake", out);
                    return;
                }
                out.add(new Event(Event.MESSAGE, body, null, type));
                return;
            default:
        }
    }

    private void startAuth(List<Event> out) {
        pcNonce = random.bytes(NONCE_SIZE);
        send(AUTH, pcNonce, out);
    }

    private byte[] proof(int who) {
        boolean pc = role == ROLE_PC;
        return Crypto.hmac(key, Crypto.cat(PROOF_LABEL, new byte[] {(byte) who}, pcNonce, phoneNonce,
                pc ? id : peerId, pc ? peerId : id));
    }

    private void sendProof(List<Event> out) {
        proofSent = true;
        send(PROOF, proof(role), out);
    }

    private void deriveSession() {
        byte[] k = Crypto.hkdf(key, Crypto.cat(pcNonce, phoneNonce), SESSION_LABEL, 96);
        byte[] toPhone = Arrays.copyOfRange(k, 0, 32), toPc = Arrays.copyOfRange(k, 32, 64);
        sendKey = role == ROLE_PC ? toPhone : toPc;
        recvKey = role == ROLE_PC ? toPc : toPhone;
        udp = Arrays.copyOfRange(k, 64, 96);
    }

    public List<Event> accept() {
        List<Event> out = new ArrayList<>();
        if (phase != PHASE_CONFIRM || acceptedHere)
            return out;
        acceptedHere = true;
        send(PAIR_ACCEPT, new byte[0], out);
        if (acceptedThere)
            pairDone(out);
        return out;
    }

    public List<Event> reject() {
        List<Event> out = new ArrayList<>();
        if (phase != PHASE_CONFIRM)
            return out;
        send(PAIR_REJECT, new byte[0], out);
        close("pairing rejected", out);
        return out;
    }

    private void pairDone(List<Event> out) {
        key = Crypto.hkdf(secret, transcript, PAIR_LABEL, 32);
        out.add(new Event(Event.PAIRED, key, null, 0));
        secret = null;
        ownPriv = null;
        phase = PHASE_AUTH;
        if (role == ROLE_PC)
            startAuth(out);
    }

    public List<Event> message(int type, byte[] body) {
        List<Event> out = new ArrayList<>();
        if (phase == PHASE_READY)
            send(type, body, out);
        return out;
    }

    // --- datagrams -------------------------------------------------------------

    // MEDIA's body (see atrium's link_core.hpp).
    public static byte[] packMedia(int status, int actions, long duration, long position, String title, String artist,
            String album, String app, byte[] art) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        byte[] head = new byte[10];
        head[0] = (byte) status;
        head[1] = (byte) actions;
        put32(head, 2, duration);
        put32(head, 6, position);
        o.write(head, 0, head.length);
        for (String s : new String[] {title, artist, album, app}) {
            byte[] b = (s == null ? "" : s).getBytes(StandardCharsets.UTF_8);
            int n = Math.min(b.length, 0xffff);
            o.write(n >>> 8);
            o.write(n);
            o.write(b, 0, n);
        }
        if (art != null)
            o.write(art, 0, art.length);
        return o.toByteArray();
    }

    // MEDIA_COMMAND's body: {command, position ms}, or null.
    public static long[] unpackMediaCommand(byte[] b) {
        if (b.length != 5 || b[0] < CMD_PLAY || b[0] > CMD_SEEK)
            return null;
        return new long[] {b[0], get(b, 1, 4)};
    }

    public static final int AUDIO_MAGIC = 0xA7, NACK_MAGIC = 0xA8;
    static final int AUDIO_LABEL = 3, NACK_LABEL = 4;
    public static final int AUDIO_HEADER = 12;
    public static final int DISCONTINUITY = 1;

    // One stream's datagrams: the phone's sound, or its microphone (mono).
    public static final class Datagrams {
        public final int audioMagic, nackMagic, audioLabel, nackLabel, frameBytes;

        Datagrams(int audioMagic, int nackMagic, int audioLabel, int nackLabel, int frameBytes) {
            this.audioMagic = audioMagic;
            this.nackMagic = nackMagic;
            this.audioLabel = audioLabel;
            this.nackLabel = nackLabel;
            this.frameBytes = frameBytes;
        }
    }

    public static final Datagrams SOUND = new Datagrams(AUDIO_MAGIC, NACK_MAGIC, AUDIO_LABEL, NACK_LABEL, FRAME_BYTES);
    public static final Datagrams MIC = new Datagrams(0xA9, 0xAA, 5, 6, 2);

    // `pcm` from `off`, `frames` frames.
    public static byte[] packAudio(Cipher c, byte[] key, int flags, int seq, int timestamp, byte[] pcm, int off, int frames) {
        return packAudio(SOUND, c, key, flags, seq, timestamp, pcm, off, frames);
    }

    public static byte[] packAudio(Datagrams kind, Cipher c, byte[] key, int flags, int seq, int timestamp, byte[] pcm,
            int off, int frames) {
        byte[] hdr = new byte[AUDIO_HEADER];
        hdr[0] = (byte) kind.audioMagic;
        hdr[1] = (byte) flags;
        hdr[2] = (byte) (frames >> 8);
        hdr[3] = (byte) frames;
        put32(hdr, 4, seq & 0xffffffffL);
        put32(hdr, 8, timestamp & 0xffffffffL);
        return Crypto.cat(hdr, Crypto.seal(c, key, Crypto.nonce(kind.audioLabel, seq & 0xffffffffL), hdr, pcm, off,
                frames * kind.frameBytes));
    }

    public static byte[] packNack(Cipher c, byte[] key, int counter, int[] seqs) {
        return packNack(SOUND, c, key, counter, seqs);
    }

    public static byte[] packNack(Datagrams kind, Cipher c, byte[] key, int counter, int[] seqs) {
        byte[] hdr = new byte[8], body = new byte[seqs.length * 4];
        hdr[0] = (byte) kind.nackMagic;
        hdr[2] = (byte) (seqs.length >> 8);
        hdr[3] = (byte) seqs.length;
        put32(hdr, 4, counter & 0xffffffffL);
        for (int i = 0; i < seqs.length; i++)
            put32(body, i * 4, seqs[i] & 0xffffffffL);
        return Crypto.cat(hdr, Crypto.seal(c, key, Crypto.nonce(kind.nackLabel, counter & 0xffffffffL), hdr, body, 0, body.length));
    }

    // The asked-for seqs, or null; out[0] gets the counter.
    public static int[] unpackNack(Cipher c, byte[] key, byte[] d, int len, long[] counter) {
        return unpackNack(SOUND, c, key, d, len, counter);
    }

    public static int[] unpackNack(Datagrams kind, Cipher c, byte[] key, byte[] d, int len, long[] counter) {
        if (len < 8 + Crypto.TAG || (d[0] & 0xff) != kind.nackMagic)
            return null;
        int count = (int) get(d, 2, 2);
        long ctr = get(d, 4, 4);
        if (len != 8 + count * 4 + Crypto.TAG)
            return null;
        byte[] body = Crypto.open(c, key, Crypto.nonce(kind.nackLabel, ctr), Arrays.copyOfRange(d, 0, 8), d, 8, len - 8);
        if (body == null)
            return null;
        int[] seqs = new int[count];
        for (int i = 0; i < count; i++)
            seqs[i] = (int) get(body, i * 4, 4);
        if (counter != null)
            counter[0] = ctr;
        return seqs;
    }
}
