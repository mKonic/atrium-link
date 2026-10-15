package dev.atrium.link;

import android.content.Context;
import android.media.AudioDeviceInfo;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import android.os.Process;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import javax.crypto.Cipher;

// The phone's whole audio output to one PC, until stopped. Loopback takes
// it with an audio policy, so nothing plays on the phone, voice calls' mode
// included; stopping gives the sound back. Where that can't register, it
// records REMOTE_SUBMIX, the default output, as scrcpy's
// --audio-source=output does (which loses the sound to the speaker while an
// app is in a call's mode). Shell holds the permissions for both, and
// neither takes notice of apps opting out of playback capture.
//
// With Link.MIC it sends the microphone instead, mono, recorded as speech
// recognisers want it (VOICE_RECOGNITION: no echo cancelling or gain
// control). The privacy indicator shows while it records.
//
// Every 5 ms of audio is a datagram (see Link's datagrams). Digital silence
// longer than SILENT_AFTER isn't sent; the next sound goes out flagged
// DISCONTINUITY. The last HISTORY datagrams are kept to resend when the PC
// asks.
final class AudioSender {
    interface Listener {
        // From the capture thread: it ended on its own (`why` null when stopped).
        void ended(String why);
    }

    private static final int SILENT_AFTER = Link.RATE / 5;  // 200 ms
    private static final int HISTORY = 1024;               // ~5 s

    private final Context ctx;
    private final Link.Datagrams kind;
    private final String tag;
    private final byte[] key;
    private final InetSocketAddress to;
    private final int frames, localPort;
    private final Listener listener;
    private volatile boolean running = true;
    private DatagramSocket socket;
    private AudioRecord record;
    private Loopback loopback;
    private Thread capture, nacks, volume;
    // The phone's volume as a gain, for a capture that comes before it.
    private volatile float gain = 1f;
    private final byte[][] sent = new byte[HISTORY][];
    private final int[] sentSeq = new int[HISTORY];
    // The next datagram's seq. It goes on from the session's last stream:
    // the key is the session's, and a seq is a nonce.
    private volatile int seq;

    // `localPort`: sent from, the same number as the link's TCP port, so
    // the PC knows where to send first (see Link's datagrams).
    AudioSender(Context ctx, Link.Datagrams kind, byte[] key, int firstSeq, InetAddress pc, int port, int frames,
            int localPort, Listener listener) {
        this.kind = kind;
        this.tag = kind == Link.MIC ? "mic: " : "audio: ";
        this.localPort = localPort;
        this.ctx = ctx;
        this.seq = firstSeq;
        this.key = key;
        this.to = new InetSocketAddress(pc, port);
        this.frames = frames > 0 && frames <= Link.PACKET_FRAMES ? frames : Link.PACKET_FRAMES;
        this.listener = listener;
    }

    // Throws when capture can't start; nothing is left running then.
    void start() throws IOException {
        AudioFormat format = new AudioFormat.Builder()
                .setSampleRate(Link.RATE)
                .setChannelMask(AudioFormat.CHANNEL_IN_STEREO)
                .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                .build();
        int min = AudioRecord.getMinBufferSize(Link.RATE, AudioFormat.CHANNEL_IN_STEREO, AudioFormat.ENCODING_PCM_16BIT);
        try {
            if (kind == Link.MIC) {
                int minMono = AudioRecord.getMinBufferSize(Link.RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT);
                record = new AudioRecord.Builder()
                    .setContext(ctx)
                    .setAudioSource(MediaRecorder.AudioSource.VOICE_RECOGNITION)
                    .setAudioFormat(new AudioFormat.Builder()
                            .setSampleRate(Link.RATE)
                            .setChannelMask(AudioFormat.CHANNEL_IN_MONO)
                            .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                            .build())
                    .setBufferSizeInBytes(Math.max(minMono, 0) * 4)
                    .build();
            } else {
                try {
                    loopback = Loopback.open(ctx, Link.RATE);
                    record = loopback.record;
                    Log.i("audio: capturing through an audio policy");
                } catch (Exception e) {
                    Throwable t = e instanceof java.lang.reflect.InvocationTargetException ? e.getCause() : e;
                    Log.i("audio: no audio policy (" + t + "), recording the default output");
                }
            }
            if (record == null)
                record = new AudioRecord.Builder()
                    .setContext(ctx)
                    .setAudioSource(MediaRecorder.AudioSource.REMOTE_SUBMIX)
                    .setAudioFormat(format)
                    .setBufferSizeInBytes(Math.max(min, 0) * 8)
                    .build();
            if (record.getState() != AudioRecord.STATE_INITIALIZED)
                throw new IOException("AudioRecord didn't initialize");
            record.startRecording();
            if (record.getRecordingState() != AudioRecord.RECORDSTATE_RECORDING)
                throw new IOException("AudioRecord didn't start");
            socket = new DatagramSocket(null);
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(localPort));
            socket.connect(to);
            // Audio class traffic: Wi-Fi's voice/video access categories.
            socket.setTrafficClass(0xb8);
        } catch (RuntimeException | IOException e) {
            release();
            throw e instanceof IOException ? (IOException) e : new IOException(e.toString(), e);
        }
        if (loopback != null) {
            gain = phoneGain((AudioManager) ctx.getSystemService(Context.AUDIO_SERVICE));
            volume = new Thread(this::followVolume, "volume");
            volume.setDaemon(true);
            volume.start();
        }
        capture = new Thread(this::capture, "audio");
        nacks = new Thread(this::nacks, "nacks");
        capture.start();
        nacks.start();
        Log.i(tag + "streaming to " + to);
    }

    void stop() {
        running = false;
        if (socket != null)
            socket.close();  // ends the nack thread's receive
        if (capture != null && capture != Thread.currentThread()) {
            try {
                capture.join(1000);
            } catch (InterruptedException ignored) {
            }
        }
        release();
    }

    private synchronized void release() {
        if (loopback != null) {
            loopback.close();
            loopback = null;
            record = null;
        }
        if (record != null) {
            try {
                record.stop();
            } catch (IllegalStateException ignored) {
            }
            record.release();
            record = null;
        }
        if (socket != null)
            socket.close();
    }

    // A policy mix is recorded at full scale: the volume buttons would do
    // nothing. They set this gain instead, read off the button's stream
    // (the call's while an app holds a call's mode, as games with voice
    // chat do) and Android's own curve for it, full volume being 0 dB.
    private static float phoneGain(AudioManager am) {
        try {
            int mode = am.getMode();
            int stream = mode == AudioManager.MODE_IN_COMMUNICATION || mode == AudioManager.MODE_IN_CALL
                    ? AudioManager.STREAM_VOICE_CALL : AudioManager.STREAM_MUSIC;
            int index = am.getStreamVolume(stream), max = am.getStreamMaxVolume(stream);
            if (am.isStreamMute(stream) || index <= 0)
                return 0f;
            float db = am.getStreamVolumeDb(stream, index, AudioDeviceInfo.TYPE_BUILTIN_SPEAKER)
                    - am.getStreamVolumeDb(stream, max, AudioDeviceInfo.TYPE_BUILTIN_SPEAKER);
            return Float.isNaN(db) ? 1f : (float) Math.min(1.0, Math.pow(10, db / 20));
        } catch (RuntimeException e) {
            return 1f;
        }
    }

    private void followVolume() {
        AudioManager am = (AudioManager) ctx.getSystemService(Context.AUDIO_SERVICE);
        while (running) {
            gain = phoneGain(am);
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    // In place, little-endian s16, ramping from `from` to `to` over the
    // buffer so a change doesn't click.
    private static void scale(byte[] pcm, float from, float to) {
        int samples = pcm.length / 2;
        float step = (to - from) / samples;
        float g = from;
        for (int i = 0; i < pcm.length; i += 2, g += step) {
            int s = (short) ((pcm[i] & 0xff) | pcm[i + 1] << 8);
            int v = Math.round(s * g);
            pcm[i] = (byte) v;
            pcm[i + 1] = (byte) (v >> 8);
        }
    }

    private void capture() {
        Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_AUDIO);
        Cipher cipher = Crypto.cipher();
        byte[] pcm = new byte[frames * kind.frameBytes];
        int timestamp = 0, silent = 0;
        boolean gap = true;  // the first packet starts the stream
        String why = null;
        long packets = 0;
        float applied = gain;
        while (running) {
            int got = 0;
            while (got < pcm.length && running) {
                AudioRecord r = record;
                int n = r == null ? -1 : r.read(pcm, got, pcm.length - got, AudioRecord.READ_BLOCKING);
                if (n < 0) {
                    if (running)
                        why = "capture read failed (" + n + ")";
                    running = false;
                    break;
                }
                got += n;
            }
            if (!running)
                break;
            if (loopback != null) {
                float g = gain;
                if (g != 1f || applied != 1f)
                    scale(pcm, applied, g);
                applied = g;
            }
            if (isSilent(pcm)) {
                silent += frames;
                if (silent > SILENT_AFTER) {
                    gap = true;
                    timestamp += frames;
                    continue;
                }
            } else {
                silent = 0;
            }
            byte[] d = Link.packAudio(kind, cipher, key, gap ? Link.DISCONTINUITY : 0, seq, timestamp, pcm, 0, frames);
            synchronized (sent) {
                sent[seq & (HISTORY - 1)] = d;
                sentSeq[seq & (HISTORY - 1)] = seq;
            }
            try {
                socket.send(new DatagramPacket(d, d.length));
            } catch (IOException e) {
                // The network blinked (Wi-Fi roaming, a full queue): the PC asks again.
            }
            gap = false;
            seq++;
            timestamp += frames;
            packets++;
        }
        Log.i(tag + "stopped after " + packets + " packets" + (why != null ? ": " + why : ""));
        release();
        listener.ended(why);
    }

    // Once stopped: where the session's next stream starts.
    int nextSeq() {
        return seq;
    }

    private static boolean isSilent(byte[] pcm) {
        for (byte b : pcm)
            if (b != 0)
                return false;
        return true;
    }

    // The PC's asks for lost packets, answered from the history.
    private void nacks() {
        Cipher cipher = Crypto.cipher();
        byte[] buf = new byte[2048];
        long last = -1;
        long resent = 0;
        while (running) {
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            try {
                socket.receive(p);
            } catch (IOException e) {
                break;
            }
            long[] counter = new long[1];
            int[] seqs = Link.unpackNack(kind, cipher, key, buf, p.getLength(), counter);
            if (seqs == null || counter[0] <= last)
                continue;  // forged, or a replay
            last = counter[0];
            for (int s : seqs) {
                byte[] d;
                synchronized (sent) {
                    d = sentSeq[s & (HISTORY - 1)] == s ? sent[s & (HISTORY - 1)] : null;
                }
                if (d == null)
                    continue;
                try {
                    socket.send(new DatagramPacket(d, d.length));
                    resent++;
                } catch (IOException ignored) {
                }
            }
        }
        Log.i(tag + "resent " + resent + " packets");
    }
}
