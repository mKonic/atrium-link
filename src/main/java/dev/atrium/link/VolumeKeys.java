package dev.atrium.link;

import android.os.Handler;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;

import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

// The phone's volume keys, taken for a PC: while on, the input devices with
// nothing but volume keys on them are grabbed (EVIOCGRAB), so Android never
// sees those keys (the volume stays put) and they come here instead. Devices
// with other keys too (the power key, a headset's buttons) are left alone.
// Closing a device lets it go, also when the daemon dies. Reading
// /dev/input takes the input group (service.sh).
final class VolumeKeys {
    interface Listener {
        // Link.KEY_VOLUME_*, on the main thread.
        void key(int key, boolean down);
    }

    private static final int EVIOCGRAB = 0x40044590;
    private static final int EV_KEY = 1, KEY_VOLUMEDOWN = 114, KEY_VOLUMEUP = 115;
    private static final int EVENT_SIZE = 24;  // struct input_event, 64-bit

    private final Handler main;
    private final Listener listener;
    private boolean wanted;
    private Thread thread;

    VolumeKeys(Handler main, Listener listener) {
        this.main = main;
        this.listener = listener;
    }

    synchronized void set(boolean on) {
        wanted = on;
        if (on && thread == null) {
            thread = new Thread(this::run, "volume-keys");
            thread.setDaemon(true);
            thread.start();
        }
    }

    private synchronized boolean keepGoing() {
        return wanted;
    }

    private void run() {
        List<FileDescriptor> fds = new ArrayList<>();
        boolean[] down = new boolean[3];
        try {
            Method grab = Os.class.getMethod("ioctlInt", FileDescriptor.class, int.class);
            for (String dev : devices()) {
                try {
                    FileDescriptor fd = Os.open("/dev/input/" + dev, OsConstants.O_RDONLY | OsConstants.O_NONBLOCK, 0);
                    fds.add(fd);
                    grab.invoke(null, fd, EVIOCGRAB);
                } catch (ErrnoException | ReflectiveOperationException e) {
                    Log.i("keys: can't take " + dev + ": " + (e.getCause() != null ? e.getCause() : e));
                }
            }
            if (fds.isEmpty())
                Log.i("keys: no volume keys to take");
            else
                Log.i("keys: taken (" + fds.size() + " devices)");
            StructPollfd[] polls = new StructPollfd[fds.size()];
            for (int i = 0; i < polls.length; i++) {
                polls[i] = new StructPollfd();
                polls[i].fd = fds.get(i);
                polls[i].events = (short) OsConstants.POLLIN;
            }
            byte[] b = new byte[EVENT_SIZE * 16];
            while (keepGoing()) {
                if (polls.length == 0 || Os.poll(polls, 250) <= 0) {
                    if (polls.length == 0)
                        Thread.sleep(250);
                    continue;
                }
                for (StructPollfd p : polls) {
                    if ((p.revents & OsConstants.POLLIN) == 0)
                        continue;
                    int n;
                    try {
                        n = Os.read(p.fd, b, 0, b.length);
                    } catch (ErrnoException | java.io.InterruptedIOException e) {
                        continue;
                    }
                    for (int i = 0; i + EVENT_SIZE <= n; i += EVENT_SIZE) {
                        int type = u16(b, i + 16), code = u16(b, i + 18), value = b[i + 20];
                        // 2 is the kernel's autorepeat: the PC repeats a held key itself.
                        if (type != EV_KEY || (value != 0 && value != 1))
                            continue;
                        int key = code == KEY_VOLUMEUP ? Link.KEY_VOLUME_UP
                                : code == KEY_VOLUMEDOWN ? Link.KEY_VOLUME_DOWN : 0;
                        if (key == 0 || down[key] == (value == 1))
                            continue;
                        down[key] = value == 1;
                        main.post(() -> listener.key(key, value == 1));
                    }
                }
            }
        } catch (ReflectiveOperationException | ErrnoException | InterruptedException e) {
            Log.i("keys: " + e);
            synchronized (this) {
                wanted = false;  // until asked again, not in a loop
            }
        } finally {
            for (FileDescriptor fd : fds) {
                try {
                    Os.close(fd);
                } catch (ErrnoException ignored) {
                }
            }
            // Nothing stays held on the PC.
            for (int key = 1; key < down.length; key++)
                if (down[key]) {
                    int k = key;
                    main.post(() -> listener.key(k, false));
                }
            Log.i("keys: given back");
            synchronized (this) {
                // Wanted again while letting go: once they're let go.
                thread = null;
                if (wanted)
                    set(true);
            }
        }
    }

    // eventN with only volume keys, by the key bitmap in sysfs: hex words,
    // the highest first, 64 bits each (the phone's kernel is 64-bit).
    private static List<String> devices() {
        List<String> out = new ArrayList<>();
        String[] names = new File("/sys/class/input").list();
        if (names == null)
            return out;
        for (String name : names) {
            if (!name.startsWith("event"))
                continue;
            String caps;
            try {
                caps = new String(Files.readAllBytes(new File("/sys/class/input/" + name + "/device/capabilities/key").toPath()),
                        StandardCharsets.UTF_8).trim();
            } catch (IOException e) {
                continue;
            }
            String[] words = caps.split("\\s+");
            boolean volume = false, other = false;
            for (int w = 0; w < words.length; w++) {
                long bits = Long.parseUnsignedLong(words[words.length - 1 - w], 16);
                for (int bit = 0; bit < 64; bit++) {
                    if ((bits >>> bit & 1) == 0)
                        continue;
                    int code = w * 64 + bit;
                    if (code == KEY_VOLUMEUP || code == KEY_VOLUMEDOWN)
                        volume = true;
                    else
                        other = true;
                }
            }
            if (volume && !other)
                out.add(name);
        }
        return out;
    }

    private static int u16(byte[] b, int i) {
        return (b[i] & 0xff) | (b[i + 1] & 0xff) << 8;
    }
}
