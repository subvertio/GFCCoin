"""
GFC Echo Hunt - a short 3D-audio game that gates rewarded plays (see docs/echo-hunt.md).

A hidden sound plays from a server-chosen direction; the player turns the phone
towards it and taps. The server keeps the answer and scores the client's report:
facing error, reaction time, and whether the recorded orientation trace looks
like a hand turning a phone (moves towards the target, not a straight synthetic
line, no teleports, plausible sample rate).

Scoring is pure (no I/O) so it can be unit-tested; storage helpers take a
connection. All tables are local to this node and never synced.

It raises the cost of botting rewarded plays; it does not stop humans paid to
play. Play Integrity and phone verification do the heavy lifting.
"""

import datetime
import json
import math
import secrets
import sqlite3
import statistics
from typing import List, Optional, Tuple

# ============================================================================
# GAME PARAMETERS
# ============================================================================

ROUNDS = 3
ROUNDS_TO_PASS = 2
CHALLENGE_TTL = datetime.timedelta(seconds=60)
PASS_VALID_FOR = datetime.timedelta(hours=24)

# Rate limit on /echohunt/start
ATTEMPT_WINDOW = datetime.timedelta(minutes=10)
MAX_ATTEMPTS_PER_WINDOW = 5

SOUNDS = ("chime", "cricket", "drip", "bell", "whistle", "owl", "frog", "click")

# Targets are at least this far from "forward" so the player has to turn
MIN_TARGET_OFFSET_DEG = 45
ELEVATION_RANGE_DEG = (-10, 20)
START_DELAY_MS_RANGE = (800, 2500)

# Tolerances
AZIMUTH_TOLERANCE_DEG = 25.0       # facing vs target, horizontal
ELEVATION_TOLERANCE_DEG = 40.0     # HRTF elevation cues are weak, so this is loose
MIN_REACTION_MS = 150
MAX_REACTION_MS = 8000
TAP_TRACE_MATCH_DEG = 10.0         # reported facing vs last trace sample
MAX_FIRST_SAMPLE_MS = 250          # the trace must start at the sound
MAX_TAP_GAP_MS = 150               # ...and run until the tap
MAX_FIRST_SAMPLE_YAW_DEG = 20.0    # yaw is zeroed when the sound starts
MIN_SAMPLES = 8
MAX_SAMPLES = 600
SAMPLE_INTERVAL_MS_RANGE = (8.0, 100.0)  # median interval: 10-125 Hz
MIN_PROGRESS = 0.6                 # share of the starting distance closed by the tap
MAX_STEP_DEG = 30.0                # largest move between two samples (teleport)
MAX_SPEED_DEG_S = 1000.0
MIN_SPEED_CV = 0.15                # constant-speed sweeps are synthetic
MIN_LINEARITY_DEVIATION = 0.06     # progress exactly proportional to time is synthetic
ELAPSED_SLACK_MS = 1000            # wall-clock time the server allows for jitter


class SubmissionError(ValueError):
    """The submission is malformed (not a scoring failure)."""


# ============================================================================
# CHALLENGES
# ============================================================================

def new_challenge(rng: Optional[secrets.SystemRandom] = None) -> dict:
    """Server-side challenge: id plus per-round target, sound and start delay."""
    rng = rng or secrets.SystemRandom()
    rounds = []
    for _ in range(ROUNDS):
        rounds.append({
            "azimuth": rng.randint(MIN_TARGET_OFFSET_DEG, 360 - MIN_TARGET_OFFSET_DEG),
            "elevation": rng.randint(*ELEVATION_RANGE_DEG),
            "sound": rng.choice(SOUNDS),
            "start_delay_ms": rng.randint(*START_DELAY_MS_RANGE),
        })
    # base64url, also valid as a Play Integrity nonce / requestHash
    return {"id": secrets.token_urlsafe(24), "rounds": rounds}


def client_view(challenge: dict) -> dict:
    """
    What the client needs to render the rounds. The direction is sent because
    the client must place the sound in 3D; the server still owns the answer
    (a client that reads it can aim perfectly, but then its trace, timing and
    Play Integrity verdict are what stop it).
    """
    return {
        "challenge_id": challenge["id"],
        "expires_in": int(CHALLENGE_TTL.total_seconds()),
        "rounds": [dict(r, index=i) for i, r in enumerate(challenge["rounds"])],
        "tolerance_deg": AZIMUTH_TOLERANCE_DEG,
        "rounds_to_pass": ROUNDS_TO_PASS,
    }


# ============================================================================
# GEOMETRY
# ============================================================================

def _unit(az: float, el: float) -> Tuple[float, float, float]:
    a, e = math.radians(az), math.radians(el)
    return (math.cos(e) * math.sin(a), math.cos(e) * math.cos(a), math.sin(e))


def angular_distance(az1: float, el1: float, az2: float, el2: float) -> float:
    """Great-circle angle in degrees between two directions."""
    u, v = _unit(az1, el1), _unit(az2, el2)
    dot = max(-1.0, min(1.0, sum(a * b for a, b in zip(u, v))))
    return math.degrees(math.acos(dot))


def azimuth_error(az1: float, az2: float) -> float:
    d = abs(az1 - az2) % 360.0
    return min(d, 360.0 - d)


# ============================================================================
# SCORING
# ============================================================================

def _number(value, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise SubmissionError(f"{what} must be a number")
    return float(value)


def parse_round(raw) -> dict:
    """Validate one submitted round: tap_ms, facing {azimuth, elevation}, samples [[t_ms, az, el], ...]."""
    if not isinstance(raw, dict):
        raise SubmissionError("each round must be an object")
    facing = raw.get("facing")
    if not isinstance(facing, dict):
        raise SubmissionError("facing must be an object")
    samples = raw.get("samples")
    if not isinstance(samples, list) or len(samples) > MAX_SAMPLES:
        raise SubmissionError(f"samples must be a list of at most {MAX_SAMPLES}")
    parsed = []
    for s in samples:
        if not isinstance(s, (list, tuple)) or len(s) != 3:
            raise SubmissionError("each sample must be [t_ms, azimuth, elevation]")
        parsed.append(tuple(_number(x, "sample value") for x in s))
    return {
        "tap_ms": _number(raw.get("tap_ms"), "tap_ms"),
        "azimuth": _number(facing.get("azimuth"), "facing.azimuth"),
        "elevation": _number(facing.get("elevation", 0.0), "facing.elevation"),
        "samples": parsed,
    }


def check_trace(samples: List[tuple], tap_ms: float, target_az: float, target_el: float) -> Optional[str]:
    """Why the orientation trace doesn't look like a person turning a phone (None if it does)."""
    if len(samples) < MIN_SAMPLES:
        return "too few orientation samples"
    times = [s[0] for s in samples]
    intervals = [b - a for a, b in zip(times, times[1:])]
    if any(dt <= 0 for dt in intervals):
        return "sample times not increasing"
    median_dt = statistics.median(intervals)
    if not SAMPLE_INTERVAL_MS_RANGE[0] <= median_dt <= SAMPLE_INTERVAL_MS_RANGE[1]:
        return "implausible sample rate"
    if times[0] < 0 or times[0] > MAX_FIRST_SAMPLE_MS:
        return "trace does not start at the sound"
    if times[-1] > tap_ms + MAX_TAP_GAP_MS or times[-1] < tap_ms - MAX_TAP_GAP_MS:
        return "trace does not end at the tap"
    if azimuth_error(samples[0][1], 0.0) > MAX_FIRST_SAMPLE_YAW_DEG:
        return "trace does not start facing forward"

    steps = [angular_distance(a[1], a[2], b[1], b[2]) for a, b in zip(samples, samples[1:])]
    if max(steps) > MAX_STEP_DEG:
        return "orientation jumped (teleport)"
    speeds = [d / (dt / 1000.0) for d, dt in zip(steps, intervals)]
    if max(speeds) > MAX_SPEED_DEG_S:
        return "turned faster than a hand can"

    start = angular_distance(samples[0][1], samples[0][2], target_az, target_el)
    end = angular_distance(samples[-1][1], samples[-1][2], target_az, target_el)
    if start <= 0 or (start - end) / start < MIN_PROGRESS:
        return "trace does not move towards the target"

    # Synthetic sweeps: constant speed, or progress exactly proportional to time
    mean_speed = statistics.fmean(speeds)
    if mean_speed <= 0 or statistics.pstdev(speeds) / mean_speed < MIN_SPEED_CV:
        return "constant-speed trace (synthetic)"
    span = times[-1] - times[0]
    deviation = 0.0
    for (t, az, el) in samples:
        progress = (start - angular_distance(az, el, target_az, target_el)) / (start - end)
        deviation = max(deviation, abs(progress - (t - times[0]) / span))
    if deviation < MIN_LINEARITY_DEVIATION:
        return "straight-line trace (synthetic)"
    return None


def score_round(target: dict, sub: dict) -> Optional[str]:
    """Why a parsed round fails (None if it passes)."""
    if sub["tap_ms"] < MIN_REACTION_MS:
        return "tap too fast"
    if sub["tap_ms"] > MAX_REACTION_MS:
        return "tap too slow"
    if azimuth_error(sub["azimuth"], target["azimuth"]) > AZIMUTH_TOLERANCE_DEG:
        return "wrong direction"
    if abs(sub["elevation"] - target.get("elevation", 0)) > ELEVATION_TOLERANCE_DEG:
        return "wrong elevation"
    trace_reason = check_trace(sub["samples"], sub["tap_ms"], target["azimuth"], target.get("elevation", 0))
    if trace_reason:
        return trace_reason
    last = sub["samples"][-1]
    if angular_distance(last[1], last[2], sub["azimuth"], sub["elevation"]) > TAP_TRACE_MATCH_DEG:
        return "facing does not match the trace"
    return None


def score_challenge(challenge: dict, rounds_raw, elapsed_ms: Optional[float] = None) -> dict:
    """
    Score a submission against the stored challenge. `elapsed_ms` is the server's
    wall-clock time from issue to submit; a submission faster than the rounds
    it claims to have played fails as a whole.
    Raises SubmissionError if the submission is malformed.
    """
    targets = challenge["rounds"]
    if not isinstance(rounds_raw, list) or len(rounds_raw) != len(targets):
        raise SubmissionError(f"expected {len(targets)} rounds")
    parsed = [parse_round(r) for r in rounds_raw]
    reasons = [score_round(t, s) for t, s in zip(targets, parsed)]

    if elapsed_ms is not None:
        claimed = sum(t["start_delay_ms"] for t in targets) + sum(max(s["tap_ms"], 0) for s in parsed)
        if elapsed_ms + ELAPSED_SLACK_MS < claimed:
            reasons = ["submitted faster than the rounds take"] * len(targets)

    passed_rounds = sum(1 for r in reasons if r is None)
    return {"passed": passed_rounds >= ROUNDS_TO_PASS, "rounds_passed": passed_rounds, "reasons": reasons}


# ============================================================================
# STORAGE (local only, never synced)
# ============================================================================

def init_echohunt_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS echohunt_challenges (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        rounds_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT
    )''')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_echohunt_challenges_user "
                 "ON echohunt_challenges (username, created_at)")
    conn.execute('''CREATE TABLE IF NOT EXISTS echohunt_passes (
        username TEXT PRIMARY KEY,
        echohunt_passed_at TEXT NOT NULL
    )''')


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def attempts_in_window(conn: sqlite3.Connection, username: str) -> int:
    since = (_now() - ATTEMPT_WINDOW).isoformat()
    return conn.execute("SELECT COUNT(*) FROM echohunt_challenges WHERE username = ? AND created_at > ?",
                        (username, since)).fetchone()[0]


def store_challenge(conn: sqlite3.Connection, username: str, challenge: dict):
    now = _now()
    # Old rows only matter for the rate limit window
    conn.execute("DELETE FROM echohunt_challenges WHERE created_at < ?",
                 ((now - max(ATTEMPT_WINDOW, CHALLENGE_TTL) * 2).isoformat(),))
    conn.execute("INSERT INTO echohunt_challenges (id, username, rounds_json, created_at, expires_at) "
                 "VALUES (?, ?, ?, ?, ?)",
                 (challenge["id"], username, json.dumps(challenge["rounds"]),
                  now.isoformat(), (now + CHALLENGE_TTL).isoformat()))


def consume_challenge(conn: sqlite3.Connection, username: str, challenge_id: str) -> Optional[dict]:
    """
    Mark the challenge used and return it with `created_at`, or None if it is
    unknown, someone else's, expired or already used. Single use: a failed
    submission burns the challenge too.
    """
    now = _now().isoformat()
    cur = conn.execute("UPDATE echohunt_challenges SET used_at = ? "
                       "WHERE id = ? AND username = ? AND used_at IS NULL AND expires_at > ?",
                       (now, challenge_id, username, now))
    conn.commit()
    if cur.rowcount != 1:
        return None
    row = conn.execute("SELECT rounds_json, created_at FROM echohunt_challenges WHERE id = ?",
                       (challenge_id,)).fetchone()
    return {"id": challenge_id, "rounds": json.loads(row[0]),
            "created_at": datetime.datetime.fromisoformat(row[1])}


def record_pass(conn: sqlite3.Connection, username: str):
    conn.execute("INSERT OR REPLACE INTO echohunt_passes (username, echohunt_passed_at) VALUES (?, ?)",
                 (username, _now().isoformat()))


def has_recent_pass(conn: sqlite3.Connection, username: str) -> bool:
    init_echohunt_tables(conn)
    row = conn.execute("SELECT echohunt_passed_at FROM echohunt_passes WHERE username = ?",
                       (username,)).fetchone()
    return bool(row) and _now() - datetime.datetime.fromisoformat(row[0]) <= PASS_VALID_FOR
