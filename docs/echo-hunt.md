# Echo Hunt

Echo Hunt is a short 3D-audio game that the GFC Android app (Unreal Engine) plays before rewarded views. A sound is hidden somewhere around the player and can only be located by ear. The player turns the phone towards it and taps. There are 3 rounds, about 15 seconds in total, and 2 of the 3 rounds must pass.

On the server:

- `echohunt.py` holds the game parameters, the scoring (pure functions) and the local tables.
- `app_echohunt.py` holds the `/echohunt/start` and `/echohunt/submit` endpoints.
- `play_integrity.py` checks Google Play Integrity.

## What it is for, and its limits

Echo Hunt is a layer that **raises the cost** of botting rewarded plays. It is not a wall.

- **What it stops.** Scripts that call `/seeds/{id}/played` directly. Emulator farms without audio-capable automation. Naive replays: every challenge is random, single use and expires after 60 seconds.
- **What it doesn't stop.**
  - **Human click farms.** A person paid to play passes, just like any other person.
  - **Determined attackers.** The client has to know each target direction to render the sound, so a modified client can read it and synthesise a convincing trace. Play Integrity, which requires the genuine app on a real device, is what makes that expensive.
- **What does the heavy lifting.**
  - Play Integrity: the genuine app from Google Play, on a device that passes integrity.
  - Phone verification: one verified phone per rewarded account.
  - The existing reward rules: the viewer account is at least 24h old, and each creator gets at most one payout per viewer per day.

  Echo Hunt sits on top of these, and it should also be fun to play.

## Switches (`/etc/gfc/gfc.env`)

| Variable | Default | Effect |
|---|---|---|
| `GFC_REQUIRE_ECHOHUNT` | `0` | `1`: a viewer's rewarded play (`/seeds/{id}/played`) also needs an Echo Hunt pass from the last 24h. Without one, the response is `credited: false` with the reason `echo hunt not passed in the last 24h`. Leave this at `0` until the Android app with Echo Hunt is released. |
| `GFC_PLAY_INTEGRITY_SA_FILE` | empty | Path to a Google Cloud service-account JSON key. The service account must be linked to the app in Play Console (Play Integrity API enabled). |
| `GFC_ANDROID_PACKAGE` | empty | The app's package name, for example `tech.galacticfederation.gfc`. |

When both Play Integrity variables are set, a passing integrity verdict is **required** for an Echo Hunt pass. When either is empty, the check is skipped, and the node logs this once.

`gfc check` shows both states.

### Third-party front ends

A third-party front end can't produce a Play Integrity token for the GFC app, so on a node with Play Integrity configured it can't earn Echo Hunt passes.

While `GFC_REQUIRE_ECHOHUNT=0`, its users' plays are protected by phone verification and the reward rules alone. A node that sets `GFC_REQUIRE_ECHOHUNT=1` with Play Integrity configured only pays plays made through the official Android app.

## Protocol

Both endpoints take form fields. Authenticate with `Authorization: Bearer <token>` (or the legacy `api_token` form field). The token needs the **`post`** scope: a pass unlocks rewarded plays, which also need `post`, so a read-only third-party token can't collect passes. Without a valid token the response is `401`, and with a token lacking `post` it is `403`.

### 1. `POST /echohunt/start`

It takes no fields besides the token.

The server allows 5 starts per user per 10 minutes. Beyond that it returns `429`.

```json
{
  "challenge_id": "q3Xb...base64url, 32 chars",
  "expires_in": 60,
  "rounds": [
    {"index": 0, "azimuth": 212, "elevation": 5,  "sound": "owl",   "start_delay_ms": 1400},
    {"index": 1, "azimuth": 77,  "elevation": -8, "sound": "drip",  "start_delay_ms": 900},
    {"index": 2, "azimuth": 301, "elevation": 14, "sound": "chime", "start_delay_ms": 2100}
  ],
  "tolerance_deg": 25.0,
  "rounds_to_pass": 2
}
```

- **Azimuth.** Degrees, clockwise, in the range 0–359, relative to where the phone faces when that round's sound starts. Targets are always at least 45° from forward, so the player has to turn.
- **Elevation.** Degrees above (+) or below (−) the horizon.
- **Sound.** One of `chime`, `cricket`, `drip`, `bell`, `whistle`, `owl`, `frog` and `click`. The app ships these as assets.
- **Start delay.** Silence before the sound starts, in milliseconds.

The server stores the challenge (`echohunt_challenges`, a local table that is never synced) and scores against its stored copy. Whatever the client claims about the targets is ignored.

### 2. Play the rounds (client)

For each round:

1. Wait `start_delay_ms`.
2. Re-zero yaw: the phone's current heading becomes azimuth 0. Elevation is absolute pitch from the horizon.
3. Start the sound at (`azimuth`, `elevation`) in the zeroed frame.
4. Record orientation samples, from the sound starting until the tap.
5. When the player taps, record the tap time and the facing direction.

### 3. Request the integrity token (client)

If the app is built with Play Integrity, request a token with the **challenge id, verbatim, as the request hash**:

- Standard API: `requestHash = challenge_id`.
- Classic API: `nonce = challenge_id`. The id is base64url, so it is a valid nonce.

Request it **after** `/echohunt/start`.

### 4. `POST /echohunt/submit`

Fields:

- the token (header, or the legacy `api_token` field)
- `challenge_id`
- `integrity_token`: optional, but required when the node has Play Integrity configured.
- `rounds`: a JSON list with one entry per round, in order.

```json
[
  {
    "tap_ms": 1480,
    "facing": {"azimuth": 205.3, "elevation": 3.1},
    "samples": [[16, 0.4, 1.2], [36, 0.5, 1.2], [52, 0.3, 1.3], "... [t_ms, azimuth, elevation]"]
  },
  "..."
]
```

- **`tap_ms`.** The tap time in milliseconds after the sound started.
- **`samples`.** Up to 600 samples per round. Each one is `[t_ms since the sound started, azimuth, elevation]`, in the same zeroed frame. Send 30–60 Hz: downsample a faster gyro, and don't smooth or resample the trace.

Responses:

| Status | Meaning |
|---|---|
| `200` | `{"ok": true, "passed": true, "rounds_passed": 3, "rounds_to_pass": 2}`. On a pass, the server records `echohunt_passed_at` for the user (`echohunt_passes`, local). Per-round failure reasons are deliberately not returned. |
| `410` | The challenge is unknown, belongs to another user, has expired, or was already used. A submission burns its challenge, including a failed one. |
| `403` | Play Integrity is required and the token is missing, invalid or not good enough. |
| `400` | The submission is malformed. |

## What the Unreal client must do

- **3D audio.** Use spatialised audio with HRTF: in Unreal, a sound attenuation with binaural (HRTF) spatialisation. Plain stereo panning can't tell front from back. The listener rotation follows the phone's orientation every frame, so turning the phone moves the sound. Ask the player to wear headphones.
- **Gyro.** Read device orientation from the rotation-vector / game-rotation sensor (gyro fused with the accelerometer). Convert it to yaw (azimuth, clockwise) and pitch (elevation), re-zero yaw at each sound start, and log samples.
- **Play Integrity.**
  - Use Google's Play Integrity API: the standard request flow through a Java/Kotlin bridge, or a Play Integrity plugin.
  - Pass the challenge id as `requestHash` (or as `nonce` with the classic API).
  - Send the token, untouched, as `integrity_token`.
  - The app must be installed from Google Play, or from an internal testing track, for `PLAY_RECOGNIZED`.
- **Timing.** Submit within 60 seconds of `/echohunt/start`. The server also checks that the time between issue and submit is at least the sum of the start delays and tap times, minus 1 second of slack.
- **UX.** Tell the player that headphones are needed. A failed attempt costs one of the 5 attempts per 10 minutes, and a pass lasts 24 hours.

## Tolerances and checks (`echohunt.py`)

A round passes only if every check below holds.

| Check | Rule |
|---|---|
| Reaction time | `tap_ms` is between 150 ms and 8 s. |
| Direction | The facing azimuth is within **25°** of the target, and the elevation within 40° (HRTF elevation cues are weak). |
| Tap vs trace | The reported facing is within 10° of the last sample. |
| Trace coverage | The first sample is ≤ 250 ms after the sound starts and faces forward (yaw within 20° of 0). The last sample is within 150 ms of the tap. |
| Sample count / rate | At least 8 samples. Times strictly increase. The median interval is between 8 and 100 ms. |
| Moves to the target | By the last sample, the angle to the target has closed by at least 60%. |
| No teleport | No step between samples is over 30°, and no speed is over 1000°/s. |
| Not synthetic | The angular speed varies (coefficient of variation ≥ 0.15). Progress towards the target is not proportional to time: it deviates from a straight line by ≥ 6% somewhere. A real turn has a reaction pause, then accelerates and decelerates. |
| Wall clock | The server-side elapsed time is at least the time the claimed rounds take (whole challenge). |

At least 2 of the 3 rounds must pass.

If Play Integrity is configured, the decoded verdict must also have:

- `requestDetails.requestPackageName == GFC_ANDROID_PACKAGE`;
- `requestDetails.requestHash` (or `nonce`) equal to the challenge id;
- a request timestamp no earlier than the challenge (with 30 s of clock skew);
- `appIntegrity.appRecognitionVerdict == PLAY_RECOGNIZED`;
- `MEETS_DEVICE_INTEGRITY` in `deviceIntegrity.deviceRecognitionVerdict`.

These numbers are first guesses. Tune them with real play data from the app: false fails annoy real players more than they slow bots.
