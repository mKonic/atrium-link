package dev.atrium.link.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Insets;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

// The one screen: pairing with a PC (the code both ends show), the PCs
// paired so far (connect, disconnect, connect automatically, share the
// microphone, media controls, forget). All of
// it is the module's daemon's state, shown as it sends it.
public final class MainActivity extends Activity {
    private final Handler main = new Handler(Looper.getMainLooper());
    private Ui ui;
    private DaemonClient daemon;
    private LinearLayout content;
    private TextView subtitle;
    private String shown;  // the status on screen: redrawn only when it changes
    private TextView left;  // the pairing window's countdown
    private long until;

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            if (left != null)
                left.setText(String.valueOf(Math.max(0, Math.round((until - System.currentTimeMillis()) / 1000.0))));
            main.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        ui = new Ui(this);
        daemon = new DaemonClient(this::render);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(ui.bg);
        LinearLayout page = ui.column();
        page.setPadding(ui.dp(16), ui.dp(16), ui.dp(16), ui.dp(16));
        scroll.addView(page);
        // Drawn under the system bars; the page keeps clear of them.
        scroll.setOnApplyWindowInsetsListener((v, insets) -> {
            Insets bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            page.setPadding(ui.dp(16) + bars.left, ui.dp(16) + bars.top, ui.dp(16) + bars.right, ui.dp(16) + bars.bottom);
            return WindowInsets.CONSUMED;
        });

        TextView title = ui.text("Atrium Link", 26, ui.fg, true);
        page.addView(title);
        subtitle = ui.note("Your phone's sound and clipboard on your Atrium PC.");
        subtitle.setPadding(0, ui.dp(2), 0, ui.dp(16));
        page.addView(subtitle);
        content = ui.column();
        page.addView(content);
        setContentView(scroll);
        render(null);
    }

    @Override
    protected void onStart() {
        super.onStart();
        daemon.start();
        main.post(tick);
    }

    @Override
    protected void onStop() {
        daemon.stop();
        main.removeCallbacks(tick);
        super.onStop();
    }

    private void render(JSONObject s) {
        String now = s == null ? "" : s.toString();
        if (now.equals(shown))
            return;
        shown = now;
        content.removeAllViews();
        left = null;
        if (s == null) {
            subtitle.setText("Your phone's sound and clipboard on your Atrium PC.");
            LinearLayout c = ui.card();
            c.addView(ui.title("The Atrium Link module isn't running"));
            TextView t = ui.note("It runs with root, as a KernelSU module. Install it in KernelSU, then restart the phone.");
            t.setPadding(0, ui.dp(4), 0, 0);
            c.addView(t);
            content.addView(c);
            return;
        }
        subtitle.setText(s.optString("name") + " · its sound and clipboard on your Atrium PC.");
        content.addView(pairing(s));
        content.addView(pcs(s));
    }

    private View pairing(JSONObject s) {
        LinearLayout c = ui.card();
        JSONObject p = s.optJSONObject("pairing");
        if (p == null)
            p = new JSONObject();
        if (!p.optString("code").isEmpty()) {
            c.addView(ui.title("Pairing with " + p.optString("pc", "a PC")));
            TextView code = ui.text(p.optString("code"), 40, ui.fg, true);
            code.setTypeface(android.graphics.Typeface.MONOSPACE, android.graphics.Typeface.BOLD);
            code.setLetterSpacing(0.15f);
            code.setGravity(Gravity.CENTER);
            code.setPadding(0, ui.dp(12), 0, ui.dp(12));
            c.addView(code);
            c.addView(ui.note("Accept if Atrium shows the same code, and accept there too."));
            LinearLayout b = ui.row();
            b.setGravity(Gravity.END);
            b.addView(ui.button("Reject", false, v -> daemon.send("reject")));
            b.addView(ui.button("Accept", true, v -> daemon.send("accept")), ui.gapLeft(8));
            c.addView(b, ui.gapTop(12));
        } else if (p.optBoolean("open")) {
            until = p.optLong("until");
            c.addView(ui.title("Waiting for a PC"));
            c.addView(ui.note("In Atrium: Settings › Phone, then Pair next to this phone under Nearby."), ui.gapTop(4));
            LinearLayout r = ui.row();
            left = ui.note("");
            r.addView(ui.note("Open for "));
            r.addView(left);
            r.addView(ui.note(" s"));
            c.addView(r, ui.gapTop(4));
            LinearLayout b = ui.row();
            b.setGravity(Gravity.END);
            b.addView(ui.button("Cancel", false, v -> daemon.send("cancel")));
            c.addView(b, ui.gapTop(12));
            left.setText(String.valueOf(Math.max(0, Math.round((until - System.currentTimeMillis()) / 1000.0))));
        } else {
            LinearLayout r = ui.row();
            LinearLayout words = ui.column();
            words.addView(ui.title("Pair a PC"));
            words.addView(ui.note("Play this phone's sound on an Atrium PC over Wi-Fi."));
            r.addView(words, Ui.grow());
            r.addView(ui.button("Pair", true, v -> daemon.send("pair")), ui.gapLeft(12));
            c.addView(r);
        }
        String error = s.optString("error");
        if (!error.isEmpty()) {
            TextView e = ui.text(error, 13, ui.bad, false);
            c.addView(e, ui.gapTop(8));
        }
        return c;
    }

    private View pcs(JSONObject s) {
        LinearLayout c = ui.card();
        c.addView(ui.title("Paired PCs"));
        JSONArray list = s.optJSONArray("pcs");
        if (list == null || list.length() == 0) {
            c.addView(ui.note("None yet."), ui.gapTop(8));
            return c;
        }
        for (int i = 0; i < list.length(); i++) {
            JSONObject pc = list.optJSONObject(i);
            if (pc != null)
                c.addView(pc(pc), ui.gapTop(i == 0 ? 12 : 20));
        }
        return c;
    }

    private View pc(JSONObject pc) {
        String id = pc.optString("id");
        String name = pc.optString("name", "PC");
        boolean connected = pc.optBoolean("connected"), calling = pc.optBoolean("calling");
        String state = pc.optBoolean("micLive") ? "Using this phone's microphone"
                : pc.optBoolean("streaming") ? "Playing this phone's sound"
                : connected ? "Connected"
                : calling ? "Asking it to connect…"
                : "Not connected";

        LinearLayout box = ui.column();
        LinearLayout r = ui.row();
        r.addView(ui.dot(connected ? ui.ok : ui.dim));
        LinearLayout words = ui.column();
        words.addView(ui.text(name, 15, ui.fg, false));
        words.addView(ui.note(state));
        r.addView(words, Ui.grow());
        if (connected) {
            r.addView(ui.button("Disconnect", false, v -> daemon.send("disconnect " + id)), ui.gapLeft(8));
        } else {
            TextView connect = ui.button("Connect", false, v -> daemon.send("connect " + id));
            connect.setEnabled(!calling);
            connect.setAlpha(calling ? 0.5f : 1f);
            r.addView(connect, ui.gapLeft(8));
        }
        r.addView(ui.button("Forget", false, v -> new AlertDialog.Builder(this)
                .setTitle("Forget " + name + "?")
                .setMessage("It will need to pair again to play this phone's sound.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Forget", (d, w) -> daemon.send("forget " + id))
                .show()), ui.gapLeft(8));
        box.addView(r);

        LinearLayout auto = ui.row();
        auto.setPadding(ui.dp(22), 0, 0, 0);
        LinearLayout words2 = ui.column();
        words2.addView(ui.text("Connect automatically", 14, ui.fg, false));
        words2.addView(ui.note("Whenever it finds this phone. Off: only when you press Connect, here or on the PC."));
        auto.addView(words2, Ui.grow());
        Switch sw = new Switch(this);
        sw.setChecked(pc.optBoolean("auto", true));
        sw.setOnCheckedChangeListener((b, on) -> daemon.send("auto " + id + (on ? " on" : " off")));
        auto.addView(sw, ui.gapLeft(12));
        box.addView(auto, ui.gapTop(8));

        LinearLayout mic = ui.row();
        mic.setPadding(ui.dp(22), 0, 0, 0);
        LinearLayout words3 = ui.column();
        words3.addView(ui.text("Share the microphone", 14, ui.fg, false));
        words3.addView(ui.note("The PC can record from it like a microphone of its own. It's only on while something there records."));
        mic.addView(words3, Ui.grow());
        Switch micSw = new Switch(this);
        micSw.setChecked(pc.optBoolean("mic"));
        micSw.setOnCheckedChangeListener((b, on) -> daemon.send("mic " + id + (on ? " on" : " off")));
        mic.addView(micSw, ui.gapLeft(12));
        box.addView(mic, ui.gapTop(8));

        LinearLayout keys = ui.row();
        keys.setPadding(ui.dp(22), 0, 0, 0);
        LinearLayout words4 = ui.column();
        words4.addView(ui.text("Media controls", 14, ui.fg, false));
        words4.addView(ui.note("While connected, volume up and down press the PC's right and left arrow keys. The phone's volume stays put."));
        keys.addView(words4, Ui.grow());
        Switch keysSw = new Switch(this);
        keysSw.setChecked(pc.optBoolean("keys"));
        keysSw.setOnCheckedChangeListener((b, on) -> daemon.send("keys " + id + (on ? " on" : " off")));
        keys.addView(keysSw, ui.gapLeft(12));
        box.addView(keys, ui.gapTop(8));
        return box;
    }
}
