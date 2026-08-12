#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xisconf - visual runtime configurator for XiS.

Tabs:
  Screens         -- monitor layout (xrandr), including per-output DPI
                     and advanced driver properties (TearFree, underscan,
                     scaling mode, PRIME Synchronization etc., whenever
                     the driver exposes them).
  Pointer/Keyboard -- pointer acceleration/scrolling/handedness/tapping
                     (xinput/libinput), key repeat and bell (xset), and
                     XiS'2 extra keyboard-related flags
                     (ToggleModifiersOnPress, KickHotkeysOnRelease).
  Wallpaper       -- per-(output, desktop) wallpaper layers managed by
                     the xisback session daemon, talked to over its
                     Unix-socket protocol (see xisback/PROTOCOL.md).
  Other           -- DPMS and screensaver (xset), XiS's 3rd extra
                     flag (DisablePrimarySelection, via xprop), and the
                     number of virtual desktops (via wmctrl, EWMH).
  Permissions     -- XNOTIFY runtime mode and ALLOW/DENY rules, talked
                     to over the xisguard control socket (see
                     xisguard/XISGUARD.md, "Socket de controle").
  About           -- info about the connected X server and its active
                     extensions (xdpyinfo).

Every tab keeps a snapshot ("baseline") of the last detected/applied
state, and the Apply button only emits commands for what actually
changed since then. Tabs with pending changes are highlighted
(bold+italic) until the next detect/apply. The Wallpaper and
Permissions tabs are the exception: their actions (SET/CLEAR layers;
ADD_RULE/REMOVE_RULE/RELOAD) act immediately on their respective
daemons (there's no staged/batched state to diff there), though they
still log every command and honor the simulation checkbox like
everything else. The "Runtime mode" group of the Permissions tab is
itself staged/diffed like the other tabs, since it's just SET_STATUS
on xisguard, not a rule change.

The bottom log is collapsed into a thin status bar by default (showing
the last logged line); click it to expand/collapse the full log.

Uses no direct C/lib bindings: everything goes through subprocess, in the
same spirit as xnsguard-gui. Compatible with PyQt6 (if available) or PyQt5.
"""

import sys
import os
import re
import copy
import json
import shlex
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    from PyQt6 import QtWidgets, QtGui, QtCore
    _QT6 = True
except ImportError:
    from PyQt5 import QtWidgets, QtGui, QtCore
    _QT6 = False


# ══════════════════════════════ Qt5/Qt6 shims ══════════════════════════════

def _qexec(w):
    return w.exec() if _QT6 else w.exec_()


def _orientation_h():
    return (QtCore.Qt.Orientation.Horizontal if _QT6
            else QtCore.Qt.Horizontal)


def _orientation_v():
    return (QtCore.Qt.Orientation.Vertical if _QT6
            else QtCore.Qt.Vertical)


def _movable():
    return (QtWidgets.QGraphicsItem.GraphicsItemFlag.ItemIsMovable if _QT6
            else QtWidgets.QGraphicsItem.ItemIsMovable)


def _selectable():
    return (QtWidgets.QGraphicsItem.GraphicsItemFlag.ItemIsSelectable if _QT6
            else QtWidgets.QGraphicsItem.ItemIsSelectable)


def _sends_geo():
    return (QtWidgets.QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges if _QT6
            else QtWidgets.QGraphicsItem.ItemSendsGeometryChanges)


def _pos_change():
    return (QtWidgets.QGraphicsItem.GraphicsItemChange.ItemPositionChange if _QT6
            else QtWidgets.QGraphicsItem.ItemPositionChange)


def _antialias():
    return (QtGui.QPainter.RenderHint.Antialiasing if _QT6
            else QtGui.QPainter.Antialiasing)


def _align_center():
    return (QtCore.Qt.AlignmentFlag.AlignCenter if _QT6
            else QtCore.Qt.AlignCenter)


# ══════════════════════════════ Data model: screens ══════════════════════════════

ROTATIONS = ["normal", "left", "inverted", "right"]
ROTATION_LABELS = {
    "normal": "Normal",
    "left": "Left (90°)",
    "right": "Right (90°)",
    "inverted": "Inverted (180°)",
}
ROTATION_LABELS_REV = {v: k for k, v in ROTATION_LABELS.items()}

# Output properties that already have dedicated UI (don't enter the
# generic "advanced properties" system).
_DEDICATED_PROPS = {"DPI"}

# Properties that are clearly internal/driver-managed -- even if they
# technically have a "range:", they make no sense as a user control
# (LUTs, color matrices, identifiers, timestamps...).
_READONLY_PROPS = {
    "GAMMA_LUT_SIZE", "DEGAMMA_LUT_SIZE", "GAMMA_LUT", "DEGAMMA_LUT",
    "CONNECTOR_ID", "vrr_capable", "link-status",
    "Identifier", "Timestamp", "Subpixel", "Gamma", "Brightness", "Clones",
    "CRTC", "CRTCs",
}

# Properties that are purely internal to other software (desktop
# environment), binary blobs, or internal driver matrices with zero
# value as a user control (CTM) -- never shown in the UI at all.
_HIDDEN_PROPS = {"EDID", "_KDE_SCREEN_INDEX", "CTM"}


@dataclass
class Mode:
    width: int
    height: int
    rates: list  # list[(rate_str, is_current, is_preferred)]

    @property
    def name(self):
        return f"{self.width}x{self.height}"


@dataclass
class Output:
    name: str
    connected: bool = False
    enabled: bool = False
    primary: bool = False
    x: int = 0
    y: int = 0
    width: int = 0
    height: int = 0
    phys_mm: Optional[tuple] = None
    rotation: str = "normal"
    dpi: Optional[int] = None
    scale_x: float = 1.0
    scale_y: float = 1.0
    modes: list = field(default_factory=list)
    current_mode: Optional[str] = None
    current_rate: Optional[str] = None
    mirror_of: Optional[str] = None

    # Generic driver properties, discovered via `xrandr --verbose`.
    # meta: name -> {"supported": [str,...] | None, "range": (lo,hi) | None}
    # values: name -> current value (string), only for editable ones (meta keys)
    # readonly: name -> current value (string), display only
    extra_props_meta: dict = field(default_factory=dict)
    extra_prop_values: dict = field(default_factory=dict)
    extra_props_readonly: dict = field(default_factory=dict)

    def mode_names(self):
        seen = []
        for m in self.modes:
            if m.name not in seen:
                seen.append(m.name)
        return seen

    def rates_for(self, mode_name):
        for m in self.modes:
            if m.name == mode_name:
                return m.rates
        return []

    def rotated_size(self):
        w, h = self.width, self.height
        if self.rotation in ("left", "right"):
            w, h = h, w
        return w, h

    def state_tuple(self):
        """Signature of the fields relevant to deciding whether this
        output needs to enter the Apply command (compared to baseline)."""
        return (self.enabled, self.primary, self.current_mode, self.current_rate,
                self.rotation, round(self.scale_x, 4), round(self.scale_y, 4),
                self.dpi, self.mirror_of, self.x, self.y,
                tuple(sorted(self.extra_prop_values.items())))


# ══════════════════════════════ xrandr parsing ══════════════════════════════

_HEADER_GEOM_RE = re.compile(r'^(\d+)x(\d+)\+(-?\d+)\+(-?\d+)$')
_XID_RE = re.compile(r'^\(0x[0-9a-fA-F]+\)$')
_MM_RE = re.compile(r'^(\d+)mm$')
_MODE_LINE_RE = re.compile(r'^\s{3}(\d+)x(\d+)\s+(.*)$')
_RATE_TOK_RE = re.compile(r'^([\d.]+)(\*?)(\+?)$')
_RANGE_RE = re.compile(r'range:\s*\((-?\d+),\s*(-?\d+)\)')


def _is_header_line(line):
    if not line or line[0].isspace():
        return False
    tokens = line.split()
    return len(tokens) >= 2 and tokens[1] in ("connected", "disconnected")


def _parse_header(line):
    tokens = line.split()
    name = tokens[0]
    i = 1
    connected = tokens[i] == "connected"
    i += 1
    primary = False
    if i < len(tokens) and tokens[i] == "primary":
        primary = True
        i += 1
    geom = None
    if i < len(tokens):
        m = _HEADER_GEOM_RE.match(tokens[i])
        if m:
            geom = tuple(int(v) for v in m.groups())
            i += 1
    if i < len(tokens) and _XID_RE.match(tokens[i]):
        i += 1
    rotation = "normal"
    if i < len(tokens) and tokens[i] in ROTATIONS:
        rotation = tokens[i]
        i += 1
    if i < len(tokens) and tokens[i].startswith("("):
        while i < len(tokens) and not tokens[i].endswith(")"):
            i += 1
        i += 1
    phys = None
    if i + 2 < len(tokens) and tokens[i + 1] == "x":
        mw = _MM_RE.match(tokens[i])
        mh = _MM_RE.match(tokens[i + 2])
        if mw and mh:
            phys = (int(mw.group(1)), int(mh.group(1)))

    out = Output(name=name, connected=connected, primary=primary,
                 rotation=rotation, phys_mm=phys)
    if geom:
        out.width, out.height, out.x, out.y = geom
        out.enabled = True
    return out


def _parse_verbose_props(text, outputs):
    """Extracts Transform (current --scale), DPI, and generically all
    other output properties (TearFree, underscan, scaling mode, PRIME
    Synchronization, HDCP, max bpc, non-desktop, etc. -- whatever the
    driver exposes), classifying them as editable (have "supported:" or
    "range:" and aren't in the blocklist) or read-only."""
    lines = text.splitlines()
    i = 0
    current = None
    while i < len(lines):
        line = lines[i]
        if _is_header_line(line):
            current = line.split()[0]
            i += 1
            continue
        if not line or not line.startswith("\t") or line.startswith("\t\t"):
            i += 1
            continue
        if current is None or current not in outputs:
            i += 1
            continue
        out = outputs[current]
        stripped = line[1:]

        if stripped.startswith("Transform:"):
            row0 = stripped.split(":", 1)[1].split()
            row1 = lines[i + 1].split() if i + 1 < len(lines) else []
            try:
                out.scale_x = float(row0[0])
                out.scale_y = float(row1[1])
            except (IndexError, ValueError):
                pass
            i += 3
            continue

        if ":" not in stripped:
            i += 1
            continue
        name, _, val = stripped.partition(":")
        name = name.strip()
        val = val.strip()

        # peek at the metadata sub-line(s) (supported:/range:), and skip
        # over any other continuation (e.g. EDID hex dump)
        supported = None
        rng = None
        j = i + 1
        while j < len(lines) and lines[j].startswith("\t\t"):
            sub = lines[j].strip()
            if sub.startswith("supported:"):
                supported = [v.strip() for v in sub.split(":", 1)[1].split(",") if v.strip()]
            elif sub.startswith("range:"):
                m = _RANGE_RE.search(sub)
                if m:
                    rng = (int(m.group(1)), int(m.group(2)))
            j += 1

        if name in _HIDDEN_PROPS:
            i = j
            continue

        if name == "DPI":
            try:
                out.dpi = int(float(val.split()[0])) if val else None
            except ValueError:
                pass
            i = j
            continue

        if name in _READONLY_PROPS or (supported is None and rng is None):
            out.extra_props_readonly[name] = val
        else:
            out.extra_props_meta[name] = {"supported": supported, "range": rng}
            out.extra_prop_values.setdefault(name, val)

        i = j


def _parse_plain_modes(text, outputs):
    """Extracts the list of modes + refresh rates (xrandr without
    --verbose, where each mode's Hz is shown directly, with '*' = current
    and '+' = preferred)."""
    current = None
    for line in text.splitlines():
        if _is_header_line(line):
            current = line.split()[0]
            continue
        if current is None or current not in outputs:
            continue
        m = _MODE_LINE_RE.match(line)
        if not m:
            continue
        w, h, rest = int(m.group(1)), int(m.group(2)), m.group(3)
        rates = []
        for tok in rest.split():
            rm = _RATE_TOK_RE.match(tok)
            if not rm:
                continue
            rate, is_cur, is_pref = rm.groups()
            rates.append((rate, bool(is_cur), bool(is_pref)))
            if is_cur:
                outputs[current].current_mode = f"{w}x{h}"
                outputs[current].current_rate = rate
        outputs[current].modes.append(Mode(w, h, rates))


def detect():
    """Runs xrandr (verbose + normal) and returns {name: Output}."""
    verbose = subprocess.run(["xrandr", "--verbose"], capture_output=True,
                             text=True, check=True).stdout
    plain = subprocess.run(["xrandr"], capture_output=True,
                           text=True, check=True).stdout

    outputs = {}
    for line in verbose.splitlines():
        if _is_header_line(line):
            out = _parse_header(line)
            outputs[out.name] = out

    _parse_verbose_props(verbose, outputs)
    _parse_plain_modes(plain, outputs)
    return outputs


def _output_args(o):
    """Arguments for ONE --output block reflecting `o`'s full current
    state. x/y are used as absolute coordinates (same frame of reference
    as xrandr) -- no global normalization, so blocks for untouched
    outputs stay identical between calls."""
    args = ["--output", o.name]
    if not o.enabled:
        args += ["--off"]
        return args

    if o.mirror_of:
        args += ["--same-as", o.mirror_of]
    else:
        mode = o.current_mode or (o.mode_names()[0] if o.mode_names() else None)
        if mode:
            args += ["--mode", mode]
        if o.current_rate:
            args += ["--rate", o.current_rate]
        args += ["--pos", f"{o.x}x{o.y}"]

    args += ["--rotate", o.rotation]
    args += ["--primary"] if o.primary else ["--noprimary"]

    sx = o.scale_x if abs(o.scale_x) > 1e-6 else 1.0
    sy = o.scale_y if abs(o.scale_y) > 1e-6 else 1.0
    args += ["--scale", f"{sx:.4f}x{sy:.4f}"]

    if o.dpi:
        args += ["--set", "DPI", str(o.dpi)]

    for name, value in sorted(o.extra_prop_values.items()):
        if value != "":
            args += ["--set", name, value]

    return args


def _output_diff_args(o, baseline):
    """Arguments for ONE --output block covering only the fields of `o`
    that changed relative to `baseline` (e.g. only the refresh rate
    changed -> only emits --output NAME --rate X, not the whole block)."""
    name = o.name

    if o.enabled != baseline.enabled:
        if not o.enabled:
            return ["--output", name, "--off"]
        # Turning an output on requires a full description
        # (mode/position/etc.); there's no sensible "diff" starting from
        # a disabled state.
        return _output_args(o)

    if not o.enabled:
        return []

    args = []
    mirror_changed = o.mirror_of != baseline.mirror_of
    if mirror_changed:
        if o.mirror_of:
            args += ["--same-as", o.mirror_of]
        else:
            mode = o.current_mode or (o.mode_names()[0] if o.mode_names() else None)
            if mode:
                args += ["--mode", mode]
            if o.current_rate:
                args += ["--rate", o.current_rate]
            args += ["--pos", f"{o.x}x{o.y}"]
    elif not o.mirror_of:
        if o.current_mode != baseline.current_mode:
            args += ["--mode", o.current_mode]
        if o.current_rate != baseline.current_rate:
            args += ["--rate", o.current_rate]
        if (o.x, o.y) != (baseline.x, baseline.y):
            args += ["--pos", f"{o.x}x{o.y}"]

    if o.rotation != baseline.rotation:
        args += ["--rotate", o.rotation]

    if o.primary != baseline.primary:
        args += ["--primary"] if o.primary else ["--noprimary"]

    if (round(o.scale_x, 4), round(o.scale_y, 4)) != \
            (round(baseline.scale_x, 4), round(baseline.scale_y, 4)):
        sx = o.scale_x if abs(o.scale_x) > 1e-6 else 1.0
        sy = o.scale_y if abs(o.scale_y) > 1e-6 else 1.0
        args += ["--scale", f"{sx:.4f}x{sy:.4f}"]

    if o.dpi != baseline.dpi and o.dpi:
        args += ["--set", "DPI", str(o.dpi)]

    for prop_name, value in sorted(o.extra_prop_values.items()):
        if value != "" and baseline.extra_prop_values.get(prop_name) != value:
            args += ["--set", prop_name, value]

    if not args:
        return []
    return ["--output", name] + args


def build_command(outputs):
    """Arguments for ONE `xrandr` call covering ALL connected outputs
    (used by --self-test; the GUI uses the "only what changed" variant,
    see MainWindow._build_changed_screen_args)."""
    args = []
    for o in outputs.values():
        if o.connected:
            args += _output_args(o)
    return args


# ══════════════════════════════ Shared helper: xinput parsing ══════════════════════════════

def _parse_xinput_props(text):
    """{property name: value (string)} from `xinput list-props` output.
    Uses the numeric "(NNN)" suffix as the exact delimiter, so that
    properties whose name is a prefix of another aren't confused (e.g.
    "... Enabled" vs "... Enabled Default")."""
    props = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or "(" not in stripped or ":" not in stripped:
            continue
        name_part, _, rest = stripped.partition(":")
        name = re.sub(r'\s*\(\d+\)\s*$', '', name_part).strip()
        props[name] = rest.strip()
    return props


# ══════════════════════════════ XiS special options (xinput/xprop) ══════════════════════════════

DISABLE_PRIMARY_SELECTION_PROP = "_DisablePrimarySelection"
TOGGLE_MODS_XI_PROP = "Toggle Lock Modifiers On Press"
KICK_HOTKEYS_XI_PROP = "Kick Hotkeys On Release"

SPECIAL_OPTION_LABELS = {
    "toggle_mods_on_press": "ToggleModifiersOnPress",
    "kick_hotkeys_on_release": "KickHotkeysOnRelease",
    "disable_primary_selection": "DisablePrimarySelection",
}


def _master_keyboard_name():
    """Name of the master keyboard XInput device (normally "Virtual core
    keyboard"); discovered via `xinput list` so as not to depend on a
    fixed name in case the server/config renames the master."""
    try:
        out = subprocess.run(["xinput", "list"], capture_output=True,
                             text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "Virtual core keyboard"
    for line in out.splitlines():
        if "master keyboard" in line.lower():
            name = line.split("id=")[0]
            name = re.sub(r'^[^\w]*', '', name).strip()
            if name:
                return name
    return "Virtual core keyboard"


def detect_special_options():
    """Reads the XiS's 3 flags: the first two via `xinput list-props` on
    the master keyboard, the third via `xprop -root`. Returns
    (flags_dict, keyboard_name, warnings)."""
    flags = {
        "toggle_mods_on_press": False,
        "kick_hotkeys_on_release": False,
        "disable_primary_selection": False,
    }
    warnings = []
    kbd = _master_keyboard_name()

    try:
        out = subprocess.run(["xinput", "list-props", kbd], capture_output=True,
                             text=True, check=True).stdout
        props = _parse_xinput_props(out)
        if TOGGLE_MODS_XI_PROP in props:
            flags["toggle_mods_on_press"] = props[TOGGLE_MODS_XI_PROP] != "0"
        if KICK_HOTKEYS_XI_PROP in props:
            flags["kick_hotkeys_on_release"] = props[KICK_HOTKEYS_XI_PROP] != "0"
    except FileNotFoundError:
        warnings.append("xinput not found in PATH.")
    except subprocess.CalledProcessError as e:
        warnings.append(f"xinput list-props failed: {e}")

    try:
        out = subprocess.run(["xprop", "-root", DISABLE_PRIMARY_SELECTION_PROP],
                             capture_output=True, text=True).stdout
        m = re.search(r'=\s*(\d+)', out)
        if m:
            flags["disable_primary_selection"] = m.group(1) != "0"
    except FileNotFoundError:
        warnings.append("xprop not found in PATH.")

    return flags, kbd, warnings


def build_special_option_command(kbd, key, value):
    ival = "1" if value else "0"
    if key == "toggle_mods_on_press":
        return ["xinput", "set-prop", kbd, TOGGLE_MODS_XI_PROP, ival]
    if key == "kick_hotkeys_on_release":
        return ["xinput", "set-prop", kbd, KICK_HOTKEYS_XI_PROP, ival]
    if key == "disable_primary_selection":
        return ["xprop", "-root", "-f", DISABLE_PRIMARY_SELECTION_PROP, "8i",
                "-set", DISABLE_PRIMARY_SELECTION_PROP, ival]
    raise ValueError(key)


# ══════════════════════════════ Pointer / touchpad (xinput + libinput) ══════════════════════════════

POINTER_PROP_NAMES = {
    "accel_speed": "libinput Accel Speed",
    "natural_scroll": "libinput Natural Scrolling Enabled",
    "left_handed": "libinput Left Handed Enabled",
    "tapping": "libinput Tapping Enabled",
}
POINTER_PROP_LABELS = {
    "accel_speed": "Pointer speed",
    "natural_scroll": "Natural scrolling",
    "left_handed": "Left-handed (swap buttons)",
    "tapping": "Tap to click (tapping)",
}


def list_pointer_devices():
    """Real XInput slave pointer devices (excludes XTEST and the virtual
    masters)."""
    try:
        out = subprocess.run(["xinput", "list", "--short"], capture_output=True,
                             text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    devices = []
    for line in out.splitlines():
        if "slave" not in line or "pointer" not in line:
            continue
        if "XTEST" in line or "Virtual core" in line:
            continue
        name = line.split("id=")[0]
        name = re.sub(r'^[^\w]*', '', name).strip()
        if name:
            devices.append(name)
    return devices


def detect_pointer_device(name):
    """Reads the current values of the libinput props supported by this
    device (missing keys = property not supported by this specific
    device, e.g. "tapping" on a mouse with no touchpad)."""
    result = {}
    try:
        out = subprocess.run(["xinput", "list-props", name], capture_output=True,
                             text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return result
    props = _parse_xinput_props(out)
    if POINTER_PROP_NAMES["accel_speed"] in props:
        try:
            result["accel_speed"] = float(props[POINTER_PROP_NAMES["accel_speed"]])
        except ValueError:
            pass
    for key in ("natural_scroll", "left_handed", "tapping"):
        propname = POINTER_PROP_NAMES[key]
        if propname in props:
            result[key] = props[propname].strip() != "0"
    return result


def build_pointer_command(device, key, value):
    propname = POINTER_PROP_NAMES[key]
    if key == "accel_speed":
        return ["xinput", "set-prop", device, propname, f"{value:.6f}"]
    return ["xinput", "set-prop", device, propname, "1" if value else "0"]


# ══════════════════════════════ Keyboard: repeat and bell (xset) ══════════════════════════════

def detect_keyboard_xset():
    result = {"repeat_enabled": True, "repeat_delay": 660, "repeat_rate": 25,
              "bell_percent": 50, "bell_pitch": 400, "bell_duration": 100}
    try:
        out = subprocess.run(["xset", "q"], capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return result
    m = re.search(r'auto repeat:\s*(on|off)', out)
    if m:
        result["repeat_enabled"] = m.group(1) == "on"
    m = re.search(r'auto repeat delay:\s*(\d+)\s*repeat rate:\s*(\d+)', out)
    if m:
        result["repeat_delay"], result["repeat_rate"] = int(m.group(1)), int(m.group(2))
    m = re.search(r'bell percent:\s*(\d+)\s*bell pitch:\s*(\d+)\s*bell duration:\s*(\d+)', out)
    if m:
        result["bell_percent"] = int(m.group(1))
        result["bell_pitch"] = int(m.group(2))
        result["bell_duration"] = int(m.group(3))
    return result


def build_keyboard_commands(current, baseline):
    cmds = []
    if current.get("repeat_enabled") != baseline.get("repeat_enabled"):
        cmds.append(("Auto repeat",
                     ["xset", "r", "on" if current["repeat_enabled"] else "off"]))
    if (current.get("repeat_delay"), current.get("repeat_rate")) != \
            (baseline.get("repeat_delay"), baseline.get("repeat_rate")):
        cmds.append(("Repeat delay/rate",
                     ["xset", "r", "rate", str(current["repeat_delay"]), str(current["repeat_rate"])]))
    if (current.get("bell_percent"), current.get("bell_pitch"), current.get("bell_duration")) != \
            (baseline.get("bell_percent"), baseline.get("bell_pitch"), baseline.get("bell_duration")):
        cmds.append(("Bell",
                     ["xset", "b", str(current["bell_percent"]), str(current["bell_pitch"]),
                      str(current["bell_duration"])]))
    return cmds


# ══════════════════════════════ Power / screen: DPMS and screensaver (xset) ══════════════════════════════

def detect_power_xset():
    result = {"dpms_enabled": True, "dpms_standby": 0, "dpms_suspend": 0, "dpms_off": 0,
              "saver_timeout": 0, "saver_cycle": 600, "prefer_blanking": True}
    try:
        out = subprocess.run(["xset", "q"], capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return result
    m = re.search(r'Standby:\s*(\d+)\s*Suspend:\s*(\d+)\s*Off:\s*(\d+)', out)
    if m:
        result["dpms_standby"], result["dpms_suspend"], result["dpms_off"] = \
            (int(x) for x in m.groups())
    result["dpms_enabled"] = "DPMS is Enabled" in out
    m = re.search(r'timeout:\s*(\d+)\s*cycle:\s*(\d+)', out)
    if m:
        result["saver_timeout"], result["saver_cycle"] = int(m.group(1)), int(m.group(2))
    m = re.search(r'prefer blanking:\s*(yes|no)', out)
    if m:
        result["prefer_blanking"] = m.group(1) == "yes"
    return result


def build_power_commands(current, baseline):
    cmds = []
    if current.get("dpms_enabled") != baseline.get("dpms_enabled"):
        cmds.append(("DPMS enabled",
                     ["xset", "+dpms" if current["dpms_enabled"] else "-dpms"]))
    dpms_now = (current.get("dpms_standby"), current.get("dpms_suspend"), current.get("dpms_off"))
    dpms_base = (baseline.get("dpms_standby"), baseline.get("dpms_suspend"), baseline.get("dpms_off"))
    if dpms_now != dpms_base:
        cmds.append(("DPMS timings", ["xset", "dpms"] + [str(x) for x in dpms_now]))
    saver_now = (current.get("saver_timeout"), current.get("saver_cycle"))
    saver_base = (baseline.get("saver_timeout"), baseline.get("saver_cycle"))
    if saver_now != saver_base:
        cmds.append(("Screensaver timeout",
                     ["xset", "s", str(saver_now[0]), str(saver_now[1])]))
    if current.get("prefer_blanking") != baseline.get("prefer_blanking"):
        cmds.append(("Prefer blanking",
                     ["xset", "s", "blank" if current["prefer_blanking"] else "noblank"]))
    return cmds


# ══════════════════════════════ Wallpaper (xisback) ══════════════════════════════
#
# xisback is a separate per-session daemon (started on demand, one
# instance guarded by flock) that owns the actual wallpaper windows. This
# talks to it over its Unix-socket, one-line-per-command protocol -- see
# xisback/PROTOCOL.md. Unlike the other tabs, there's no local
# "detected state vs. edited state" to diff and stage for Apply: SET/
# CLEAR take effect on the running daemon immediately, so this tab acts
# right away on each button click (still honoring the global simulation
# checkbox, which only logs the command instead of sending it).

WALLPAPER_MODES = ["fill", "stretch"]


def _xisback_socket_path():
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
    return os.path.join(runtime_dir, "xisback.sock")


def _xisback_connect_once():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3.0)
    s.connect(_xisback_socket_path())
    return s


def _xisback_send(cmd):
    """Sends ONE command line to the xisback daemon (connect, write
    the line, half-close, read until EOF, close) and returns the raw
    response text. If the daemon isn't reachable yet, starts it and
    retries once, per the protocol doc's guidance -- no separate
    "is it running" probe needed."""
    try:
        s = _xisback_connect_once()
    except OSError:
        try:
            subprocess.Popen(["xisback"], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
        except FileNotFoundError as e:
            raise OSError("xisback executable not found in PATH") from e
        time.sleep(0.3)
        s = _xisback_connect_once()
    with s:
        s.sendall(cmd.encode() + b"\n")
        s.shutdown(socket.SHUT_WR)
        return b"".join(iter(lambda: s.recv(4096), b"")).decode()


def xisback_list():
    """Returns a list of {"output", "desktop", "mode", "interval",
    "shuffle", "fade_ms", "path"} dicts, one per active layer, or None if
    the daemon couldn't be reached at all (as opposed to an empty list,
    which just means no layers are set)."""
    try:
        resp = _xisback_send("LIST")
    except OSError:
        return None
    layers = []
    for line in resp.splitlines():
        parts = line.split("\t")
        if len(parts) == 7:
            layers.append(dict(zip(("output", "desktop", "mode", "interval", "shuffle", "fade_ms", "path"), parts)))
    return layers


def xisback_get_actions():
    """Returns a {"left", "right", "middle", "double"} dict of the
    currently configured click-action commands (global, not per-layer), or
    None if the daemon couldn't be reached."""
    try:
        resp = _xisback_send("ACTIONS")
    except OSError:
        return None
    lines = resp.splitlines()
    parts = lines[0].split("\t") if lines else []
    parts += [""] * (4 - len(parts))
    return dict(zip(("left", "right", "middle", "double"), parts[:4]))


def detect_desktop_count():
    """Number of virtual desktops via the root window's NETWM property,
    used to populate the desktop picker (SET's <desktop> field is a
    0-based NETWM desktop index, or "*" for all of them)."""
    try:
        out = subprocess.run(["xprop", "-root", "_NET_NUMBER_OF_DESKTOPS"],
                             capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return 1
    m = re.search(r'=\s*(\d+)', out)
    return int(m.group(1)) if m else 1


def build_desktop_count_command(count):
    return ["wmctrl", "-n", str(count)]


# ══════════════════════════════ Permissions (xisguard) ══════════════════════════════
#
# xisguard is the XNOTIFY permission daemon (see xisguard/XISGUARD.md). This
# tab talks to its *control* socket -- a separate SOCK_STREAM channel from
# the xnotify.sock/xperms.sock pair it uses with the XServer -- at
# $XDG_RUNTIME_DIR/xisguard-ctl.<display>.sock. Protocol: one connection =
# one JSON request line -> one JSON response line, connection closed by the
# server. Unlike xisback, xisconf never auto-starts xisguard: it's a
# permission gate, so silently launching it behind the user's back would be
# surprising for a security-relevant daemon.

XNOTIFY_ACTIONS = [
    ("ALL", "All actions"),
    ("ATTACH", "Use shared memory"),
    ("SELECTION", "Access clipboard"),
    ("COMPOSITE", "Access other windows"),
    ("SCREEN", "Capture and draw to the screen"),
    ("RECORD", "Record events - like keystrokes"),
    ("CURSOR", "Access cursor (mouse) image and position"),
    ("INPUT_GRAB", "Grab mouse or keyboard"),
    ("INPUT_INJECT", "Insert keystrokes"),
    ("HOTKEY", "Register global hotkeys"),
    ("INPUT", "Capture input - even when unfocused"),
    ("MANAGE", "List and get properties of other windows"),
    ("GRAB_OVERRIDE", "Allow to steal a grab (for screensavers)"),
    ("WARP", "Move the mouse cursor"),
    ("FOCUS", "Steal input focus"),
    ("RANDR", "Change display configuration"),
    ("OVERLAY", "Create overlay (transparent) window"),
]


def _xisguard_ctl_socket_path():
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
    m = re.match(r'^:(\d+)', os.environ.get("DISPLAY", ":0"))
    display = int(m.group(1)) if m else 0
    return os.path.join(runtime_dir, f"xisguard-ctl.{display}.sock")


def _xisguard_ctl_send(req):
    """Sends ONE JSON request line to the xisguard control socket and
    returns the parsed JSON response (or raises OSError/ValueError if the
    daemon isn't reachable or replied with garbage)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect(_xisguard_ctl_socket_path())
        s.sendall((json.dumps(req) + "\n").encode())
        s.shutdown(socket.SHUT_WR)
        data = b"".join(iter(lambda: s.recv(65536), b""))
    finally:
        s.close()
    return json.loads(data.decode())


def detect_xisguard_status():
    """GET_STATUS -> {"version","display","no_pause","quiet",
    "always_kill","log_level"}, or None if xisguard isn't reachable."""
    try:
        resp = _xisguard_ctl_send({"cmd": "GET_STATUS"})
    except (OSError, ValueError):
        return None
    return resp if resp.get("ok") else None


def list_xisguard_rules():
    """LIST_RULES -> [{"type","action","pattern"}, ...], or None if
    xisguard isn't reachable."""
    try:
        resp = _xisguard_ctl_send({"cmd": "LIST_RULES"})
    except (OSError, ValueError):
        return None
    return resp.get("rules", []) if resp.get("ok") else None


# ══════════════════════════════ About: server info (xdpyinfo) ══════════════════════════════

def detect_server_info():
    """Name, version, vendor and list of extensions via `xdpyinfo`."""
    info = {"name": "?", "version": "?", "vendor": "?", "release": "?", "extensions": []}
    try:
        out = subprocess.run(["xdpyinfo"], capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return info
    m = re.search(r'name of display:\s*(\S+)', out)
    if m:
        info["name"] = m.group(1)
    m = re.search(r'version number:\s*(\S+)', out)
    if m:
        info["version"] = m.group(1)
    m = re.search(r'vendor string:\s*(.+)', out)
    if m:
        info["vendor"] = m.group(1).strip()
    m = re.search(r'vendor release number:\s*(\S+)', out)
    if m:
        info["release"] = m.group(1)
    m = re.search(r'number of extensions:\s*\d+\s*\n((?:\s+\S.*\n?)+)', out)
    if m:
        info["extensions"] = [ln.strip() for ln in m.group(1).splitlines() if ln.strip()]
    return info


# ══════════════════════════════ Graphics item (monitor) ══════════════════════════════

SNAP_PX = 12
FILL_PRIMARY = "#3daee9"
FILL_NORMAL = "#5b6472"
SELECT_BORDER = "#e0b23c"      # muted highlight (amber) for the selected screen
NORMAL_BORDER = "#ffffff"


class OutputItem(QtWidgets.QGraphicsObject):
    positionChanged = QtCore.pyqtSignal()
    clicked = QtCore.pyqtSignal(str)

    def __init__(self, output: Output, px_per_unit: float, dpi_visual: bool = True):
        super().__init__()
        self.output = output
        self.px_per_unit = px_per_unit
        self.dpi_visual = dpi_visual
        self.setFlag(_movable(), True)
        self.setFlag(_selectable(), True)
        self.setFlag(_sends_geo(), True)

    def dpi_factor(self):
        return (self.output.dpi or 96) / 96.0

    def effective_factor(self):
        """Combined visual factor: classic Scale (grows) / DPI (shrinks).
        >100% = square bigger than the real resolution; <100% = smaller."""
        dpi_f = self.dpi_factor() or 1.0
        sx = self.output.scale_x or 1.0
        sy = self.output.scale_y or 1.0
        return (sx * sy) ** 0.5 / dpi_f

    def logical_size(self):
        """"Logical" size (real resolution * Scale / DPI), KDE Wayland
        KCM style: what actually gets drawn when dpi_visual=True."""
        w, h = self.output.rotated_size()
        dpi_f = self.dpi_factor() or 1.0
        sx = self.output.scale_x or 1.0
        sy = self.output.scale_y or 1.0
        return round(w * sx / dpi_f), round(h * sy / dpi_f)

    def size_px(self):
        if self.dpi_visual:
            w, h = self.logical_size()
        else:
            w, h = self.output.rotated_size()
        return w * self.px_per_unit, h * self.px_per_unit

    def boundingRect(self):
        w, h = self.size_px()
        return QtCore.QRectF(0, 0, max(w, 1), max(h, 1))

    def paint(self, painter, option, widget=None):
        painter.setRenderHint(_antialias())
        rect = self.boundingRect()

        # Fill color is always fixed by role (blue = primary, gray = the
        # rest); never varies with selection/hover, so as not to confuse
        # "which one is primary" with "which one is selected".
        fill = QtGui.QColor(FILL_PRIMARY if self.output.primary else FILL_NORMAL)
        painter.setBrush(QtGui.QBrush(fill))

        if self.isSelected():
            pen = QtGui.QPen(QtGui.QColor(SELECT_BORDER), 3)
        else:
            pen = QtGui.QPen(QtGui.QColor(NORMAL_BORDER), 2)
        painter.setPen(pen)
        painter.drawRoundedRect(rect.adjusted(1, 1, -1, -1), 8, 8)

        w, h = self.output.rotated_size()
        star = "  ★" if self.output.primary else ""

        lines = [f"{self.output.name}{star}", f"{w}x{h}"]
        small_lines = []
        if self.dpi_visual:
            pct = round(self.effective_factor() * 100)
            if pct != 100:
                lines.append(f"@{pct}%")
            lw, lh = self.logical_size()
            if (lw, lh) != (w, h):
                small_lines.append(f"{lw}x{lh}")
        if self.output.mirror_of:
            small_lines.append(f"(mirrors {self.output.mirror_of})")

        main_px = max(13, min(rect.width(), rect.height()) * 0.16)
        small_px = max(9, main_px * 0.62)

        main_font = QtGui.QFont()
        main_font.setPixelSize(int(main_px))
        main_font.setBold(True)
        small_font = QtGui.QFont()
        small_font.setPixelSize(int(small_px))
        small_font.setBold(False)

        fm_main = QtGui.QFontMetrics(main_font)
        fm_small = QtGui.QFontMetrics(small_font)
        total_h = fm_main.height() * len(lines) + fm_small.height() * len(small_lines)
        y = rect.center().y() - total_h / 2

        painter.setPen(QtGui.QColor(NORMAL_BORDER))
        for line in lines:
            painter.setFont(main_font)
            line_rect = QtCore.QRectF(rect.left(), y, rect.width(), fm_main.height())
            painter.drawText(line_rect, _align_center(), line)
            y += fm_main.height()
        for line in small_lines:
            painter.setFont(small_font)
            line_rect = QtCore.QRectF(rect.left(), y, rect.width(), fm_small.height())
            painter.drawText(line_rect, _align_center(), line)
            y += fm_small.height()

    def mousePressEvent(self, event):
        self.clicked.emit(self.output.name)
        super().mousePressEvent(event)

    def itemChange(self, change, value):
        if change == _pos_change() and self.scene() is not None:
            value = self._snap(value)
        result = super().itemChange(change, value)
        if change == _pos_change():
            self.positionChanged.emit()
        return result

    def _snap(self, new_pos):
        w, h = self.size_px()
        my_left, my_top = new_pos.x(), new_pos.y()
        my_right, my_bottom = my_left + w, my_top + h

        best_dx = None
        best_dy = None
        for item in self.scene().items():
            if item is self or not isinstance(item, OutputItem):
                continue
            ow, oh = item.size_px()
            ol, ot = item.pos().x(), item.pos().y()
            or_, ob = ol + ow, ot + oh

            for a, b in ((my_left, ol), (my_left, or_), (my_right, ol), (my_right, or_)):
                if abs(a - b) <= SNAP_PX:
                    cand = b - (a - my_left)
                    if best_dx is None or abs(cand - my_left) < abs(best_dx - my_left):
                        best_dx = cand
            for a, b in ((my_top, ot), (my_top, ob), (my_bottom, ot), (my_bottom, ob)):
                if abs(a - b) <= SNAP_PX:
                    cand = b - (a - my_top)
                    if best_dy is None or abs(cand - my_top) < abs(best_dy - my_top):
                        best_dy = cand

        return QtCore.QPointF(
            best_dx if best_dx is not None else new_pos.x(),
            best_dy if best_dy is not None else new_pos.y(),
        )


# ══════════════════════════════ Main window ══════════════════════════════

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, dry_run=False):
        super().__init__()
        self.setWindowTitle("xisconf")
        self.resize(620, 410)

        # --- screens ---
        self.outputs: dict[str, Output] = {}
        self.baseline_outputs: dict[str, Output] = {}
        self.items: dict[str, OutputItem] = {}
        self.selected: Optional[str] = None
        self.px_per_unit = 0.08
        self.world_origin = (0, 0)
        self._updating_panel = False

        # --- special options ---
        self.baseline_flags: dict[str, bool] = {}
        self._keyboard_device = "Virtual core keyboard"

        # --- pointer ---
        self.pointer_devices: list[str] = []
        self.pointer_state: dict[str, dict] = {}
        self.baseline_pointer_state: dict[str, dict] = {}
        self.selected_pointer_device: Optional[str] = None

        # --- keyboard (repeat/bell) ---
        self.keyboard_state: dict = {}
        self.baseline_keyboard_state: dict = {}

        # --- power/screen ---
        self.power_state: dict = {}
        self.baseline_power_state: dict = {}

        # --- desktops (workspace count) ---
        self.wmctrl_available = shutil.which("wmctrl") is not None
        self.desktop_count = 1
        self.baseline_desktop_count = 1

        # --- permissions (xisguard) ---
        self.xisguard_online = False
        self.xisguard_status: dict = {}
        self.baseline_xisguard_status: dict = {}
        self.xisguard_rules: list = []

        # --- log status bar ---
        self._last_log_line = None

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root = QtWidgets.QVBoxLayout(central)

        # ---- toolbar (global: covers all tabs) ----
        bar = QtWidgets.QHBoxLayout()
        self.btn_detect = QtWidgets.QPushButton("Detect")
        self.btn_apply = QtWidgets.QPushButton("Apply")
        self.chk_dry_run = QtWidgets.QCheckBox("Simulation mode (don't execute)")
        self.chk_dry_run.setChecked(dry_run)
        bar.addWidget(self.btn_detect)
        bar.addWidget(self.btn_apply)
        bar.addWidget(self.chk_dry_run)
        bar.addStretch(1)
        self.lbl_pending = QtWidgets.QLabel("No pending changes.")
        self.lbl_pending.setStyleSheet(f"color: {SELECT_BORDER}; font-weight: bold;")
        bar.addWidget(self.lbl_pending)
        root.addLayout(bar)

        # ---- tabs ----
        self.tabs = QtWidgets.QTabWidget()
        root.addWidget(self.tabs, 1)
        self._tab_index_screens = self.tabs.addTab(self._build_screens_tab(), "Screens")
        self._tab_index_pointer_kbd = self.tabs.addTab(
            self._build_pointer_keyboard_tab(), "Pointer/Keyboard")
        self.tabs.addTab(self._build_wallpaper_tab(), "Wallpaper")
        self._tab_index_other = self.tabs.addTab(self._build_other_tab(), "Other")
        self._tab_index_permissions = self.tabs.addTab(
            self._build_permissions_tab(), "Permissions")
        self.tabs.addTab(self._build_about_tab(), "About")

        # ---- log (global): collapsed into a status bar by default ----
        self.btn_log_toggle = QtWidgets.QPushButton()
        self.btn_log_toggle.setCheckable(True)
        self.btn_log_toggle.setFlat(True)
        self.btn_log_toggle.setStyleSheet("text-align: left; padding: 2px;")
        self.btn_log_toggle.toggled.connect(self._toggle_log)
        root.addWidget(self.btn_log_toggle)

        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(160)
        self.log.setVisible(False)
        root.addWidget(self.log)
        self._set_log_bar_text()

        self.btn_detect.clicked.connect(self.refresh)
        self.btn_apply.clicked.connect(self.apply)

        self.refresh()

    # ---------------------------------------------------------------- Screens tab

    def _build_screens_tab(self):
        tab = QtWidgets.QWidget()
        tab_layout = QtWidgets.QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)

        # Vertical split (canvas on top, properties below): the window is
        # narrow by default, so a side-by-side layout would squeeze the
        # canvas too much. The canvas here is a small overview; detailed
        # editing happens in the panel below.
        splitter = QtWidgets.QSplitter(_orientation_v())
        tab_layout.addWidget(splitter, 1)

        canvas_container = QtWidgets.QWidget()
        canvas_layout = QtWidgets.QVBoxLayout(canvas_container)
        canvas_layout.setContentsMargins(0, 0, 0, 0)

        self.scene = QtWidgets.QGraphicsScene()
        self.view = QtWidgets.QGraphicsView(self.scene)
        self.view.setBackgroundBrush(QtGui.QColor("#232629"))
        self.view.setMinimumHeight(120)
        canvas_layout.addWidget(self.view, 1)

        self.chk_dpi_visual = QtWidgets.QCheckBox(
            "Drawing responds to DPI and Scale (shrinks/grows the box per output)")
        self.chk_dpi_visual.setChecked(False)
        self.chk_dpi_visual.toggled.connect(lambda _checked: self._rebuild_scene())
        canvas_layout.addWidget(self.chk_dpi_visual)

        splitter.addWidget(canvas_container)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setMinimumHeight(200)
        panel_container = QtWidgets.QWidget()
        scroll.setWidget(panel_container)
        splitter.addWidget(scroll)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([160, 500])
        self._build_panel(panel_container)

        return tab

    def _build_panel(self, container):
        outer = QtWidgets.QVBoxLayout(container)

        grp_mon = QtWidgets.QGroupBox("Selected monitor")
        form = QtWidgets.QFormLayout(grp_mon)

        self.cmb_monitor = QtWidgets.QComboBox()
        self.cmb_monitor.currentTextChanged.connect(self._select_from_combo)
        form.addRow("Monitor:", self.cmb_monitor)

        self.lbl_status = QtWidgets.QLabel("-")
        form.addRow("Status:", self.lbl_status)

        self.chk_enabled = QtWidgets.QCheckBox("Enabled")
        self.chk_enabled.toggled.connect(self._on_enabled)
        form.addRow(self.chk_enabled)

        self.chk_primary = QtWidgets.QCheckBox("Primary monitor")
        self.chk_primary.toggled.connect(self._on_primary)
        form.addRow(self.chk_primary)

        self.cmb_resolution = QtWidgets.QComboBox()
        self.cmb_resolution.currentTextChanged.connect(self._on_resolution)
        form.addRow("Resolution:", self.cmb_resolution)

        self.cmb_rate = QtWidgets.QComboBox()
        self.cmb_rate.currentTextChanged.connect(self._on_rate)
        form.addRow("Refresh rate:", self.cmb_rate)

        self.cmb_rotation = QtWidgets.QComboBox()
        self.cmb_rotation.addItems(list(ROTATION_LABELS.values()))
        self.cmb_rotation.currentTextChanged.connect(self._on_rotation)
        form.addRow("Rotation:", self.cmb_rotation)

        self.cmb_mirror = QtWidgets.QComboBox()
        self.cmb_mirror.currentTextChanged.connect(self._on_mirror)
        form.addRow("Mirror:", self.cmb_mirror)

        self.lbl_pos = QtWidgets.QLabel("-")
        form.addRow("Position:", self.lbl_pos)

        self.spin_dpi = QtWidgets.QSpinBox()
        self.spin_dpi.setRange(48, 960)
        self.spin_dpi.setSingleStep(12)
        self.spin_dpi.valueChanged.connect(self._on_dpi)
        form.addRow("DPI:", self.spin_dpi)
        self.lbl_dpi_factor = QtWidgets.QLabel("-")
        form.addRow("Equivalent factor:", self.lbl_dpi_factor)

        self.lbl_dpi_warning = QtWidgets.QLabel(
            "DPI below 96 isn't recommended — leave it at 96 and use "
            "Scale below instead. When you click Apply, this is "
            "converted automatically (DPI goes back to 96 and the "
            "equivalent Scale is computed).")
        self.lbl_dpi_warning.setWordWrap(True)
        self.lbl_dpi_warning.setStyleSheet("color: #e0b23c;")
        self.lbl_dpi_warning.setVisible(False)
        form.addRow(self.lbl_dpi_warning)

        self.spin_scale = QtWidgets.QDoubleSpinBox()
        self.spin_scale.setRange(0.25, 4.0)
        self.spin_scale.setSingleStep(0.05)
        self.spin_scale.setDecimals(2)
        self.spin_scale.valueChanged.connect(self._on_scale)
        form.addRow("Scale:", self.spin_scale)

        # ---- advanced driver properties (dynamic, per output) ----
        self.grp_extra_editable = QtWidgets.QGroupBox(
            "Advanced properties (TearFree, underscan, scaling, PRIME, ...)")
        self.form_extra_editable = QtWidgets.QFormLayout(self.grp_extra_editable)

        row_top = QtWidgets.QHBoxLayout()
        row_top.addWidget(grp_mon, 1)
        row_top.addWidget(self.grp_extra_editable, 1)
        outer.addLayout(row_top)

        # Read-only properties can pile up (LUTs aside, some drivers expose
        # a dozen+), so they're split into 2 side-by-side forms (2 pairs of
        # label:value columns) instead of one long single-column list.
        self.grp_extra_readonly = QtWidgets.QGroupBox("Other properties (read-only)")
        readonly_row = QtWidgets.QHBoxLayout(self.grp_extra_readonly)
        self.form_extra_readonly = QtWidgets.QFormLayout()
        self.form_extra_readonly2 = QtWidgets.QFormLayout()
        readonly_row.addLayout(self.form_extra_readonly)
        readonly_row.addLayout(self.form_extra_readonly2)
        outer.addWidget(self.grp_extra_readonly)

        outer.addStretch(1)

        self._panel_widgets = [
            self.chk_enabled, self.chk_primary, self.cmb_resolution,
            self.cmb_rate, self.cmb_rotation, self.cmb_mirror,
            self.spin_dpi, self.spin_scale,
        ]

    def _rebuild_extra_props(self, out):
        while self.form_extra_editable.rowCount():
            self.form_extra_editable.removeRow(0)
        while self.form_extra_readonly.rowCount():
            self.form_extra_readonly.removeRow(0)
        while self.form_extra_readonly2.rowCount():
            self.form_extra_readonly2.removeRow(0)

        for name in sorted(out.extra_props_meta):
            meta = out.extra_props_meta[name]
            value = out.extra_prop_values.get(name, "")
            widget = self._make_extra_prop_widget(out, name, meta, value)
            self.form_extra_editable.addRow(name + ":", widget)
        self.grp_extra_editable.setVisible(bool(out.extra_props_meta))

        readonly_names = sorted(out.extra_props_readonly)
        half = (len(readonly_names) + 1) // 2
        for i, name in enumerate(readonly_names):
            lbl = QtWidgets.QLabel(out.extra_props_readonly[name] or "-")
            target = self.form_extra_readonly if i < half else self.form_extra_readonly2
            target.addRow(name + ":", lbl)
        self.grp_extra_readonly.setVisible(bool(out.extra_props_readonly))

    def _make_extra_prop_widget(self, out, name, meta, value):
        supported, rng = meta["supported"], meta["range"]
        if supported:
            w = QtWidgets.QComboBox()
            w.addItems(supported)
            if value in supported:
                w.setCurrentText(value)
            w.currentTextChanged.connect(
                lambda text, o=out, n=name: self._on_extra_prop(o, n, text))
            return w
        if rng == (0, 1):
            w = QtWidgets.QCheckBox()
            w.setChecked(value not in ("0", ""))
            w.toggled.connect(
                lambda checked, o=out, n=name: self._on_extra_prop(o, n, "1" if checked else "0"))
            return w
        if rng:
            w = QtWidgets.QSpinBox()
            w.setRange(rng[0], rng[1])
            try:
                w.setValue(int(value))
            except ValueError:
                pass
            w.valueChanged.connect(
                lambda v, o=out, n=name: self._on_extra_prop(o, n, str(v)))
            return w
        return QtWidgets.QLabel(value)

    def _on_extra_prop(self, out, name, value):
        if self._updating_panel:
            return
        out.extra_prop_values[name] = value
        self._update_dirty_indicators()

    # ---------------------------------------------------------------- Pointer/Keyboard tab

    def _build_pointer_keyboard_tab(self):
        outer_tab = QtWidgets.QWidget()
        outer_layout = QtWidgets.QVBoxLayout(outer_tab)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        outer_layout.addWidget(scroll)

        tab = QtWidgets.QWidget()
        scroll.setWidget(tab)
        layout = QtWidgets.QVBoxLayout(tab)

        grp = QtWidgets.QGroupBox("Pointer device")
        form = QtWidgets.QFormLayout(grp)

        self.cmb_pointer_device = QtWidgets.QComboBox()
        self.cmb_pointer_device.currentTextChanged.connect(self._select_pointer_device)
        form.addRow("Device:", self.cmb_pointer_device)

        self.spin_pointer_accel = QtWidgets.QDoubleSpinBox()
        self.spin_pointer_accel.setRange(-1.0, 1.0)
        self.spin_pointer_accel.setSingleStep(0.1)
        self.spin_pointer_accel.setDecimals(2)
        self.spin_pointer_accel.valueChanged.connect(self._on_pointer_field("accel_speed"))
        form.addRow("Speed (Accel Speed):", self.spin_pointer_accel)

        self.chk_pointer_natural_scroll = QtWidgets.QCheckBox("Natural scrolling")
        self.chk_pointer_natural_scroll.toggled.connect(self._on_pointer_field("natural_scroll"))
        form.addRow(self.chk_pointer_natural_scroll)

        self.chk_pointer_left_handed = QtWidgets.QCheckBox("Left-handed (swap buttons)")
        self.chk_pointer_left_handed.toggled.connect(self._on_pointer_field("left_handed"))
        form.addRow(self.chk_pointer_left_handed)

        self.chk_pointer_tapping = QtWidgets.QCheckBox("Tap to click (tapping, touchpads)")
        self.chk_pointer_tapping.toggled.connect(self._on_pointer_field("tapping"))
        form.addRow(self.chk_pointer_tapping)

        layout.addWidget(grp)
        note = QtWidgets.QLabel(
            "Read/applied via xinput (libinput properties). Controls are "
            "disabled when the selected device doesn't support that "
            "property (e.g. tapping on a mouse with no touchpad).")
        note.setWordWrap(True)
        layout.addWidget(note)

        grp_kbd = QtWidgets.QGroupBox("Key repeat")
        form_kbd = QtWidgets.QFormLayout(grp_kbd)

        self.chk_kbd_repeat = QtWidgets.QCheckBox("Auto repeat enabled")
        self.chk_kbd_repeat.toggled.connect(lambda v: self._set_kbd("repeat_enabled", v))
        form_kbd.addRow(self.chk_kbd_repeat)

        self.spin_kbd_delay = QtWidgets.QSpinBox()
        self.spin_kbd_delay.setRange(100, 3000)
        self.spin_kbd_delay.setSuffix(" ms")
        self.spin_kbd_delay.valueChanged.connect(lambda v: self._set_kbd("repeat_delay", v))
        form_kbd.addRow("Initial delay:", self.spin_kbd_delay)

        self.spin_kbd_rate = QtWidgets.QSpinBox()
        self.spin_kbd_rate.setRange(1, 100)
        self.spin_kbd_rate.setSuffix(" rep/s")
        self.spin_kbd_rate.valueChanged.connect(lambda v: self._set_kbd("repeat_rate", v))
        form_kbd.addRow("Repeat rate:", self.spin_kbd_rate)

        row_kbd_bell = QtWidgets.QHBoxLayout()
        row_kbd_bell.addWidget(grp_kbd, 1)

        grp_bell = QtWidgets.QGroupBox("Bell")
        form_bell = QtWidgets.QFormLayout(grp_bell)

        self.spin_bell_percent = QtWidgets.QSpinBox()
        self.spin_bell_percent.setRange(0, 100)
        self.spin_bell_percent.setSuffix(" %")
        self.spin_bell_percent.valueChanged.connect(lambda v: self._set_kbd("bell_percent", v))
        form_bell.addRow("Volume:", self.spin_bell_percent)

        self.spin_bell_pitch = QtWidgets.QSpinBox()
        self.spin_bell_pitch.setRange(1, 5000)
        self.spin_bell_pitch.setSuffix(" Hz")
        self.spin_bell_pitch.valueChanged.connect(lambda v: self._set_kbd("bell_pitch", v))
        form_bell.addRow("Pitch:", self.spin_bell_pitch)

        self.spin_bell_duration = QtWidgets.QSpinBox()
        self.spin_bell_duration.setRange(0, 5000)
        self.spin_bell_duration.setSuffix(" ms")
        self.spin_bell_duration.valueChanged.connect(lambda v: self._set_kbd("bell_duration", v))
        form_bell.addRow("Duration:", self.spin_bell_duration)

        row_kbd_bell.addWidget(grp_bell, 1)
        layout.addLayout(row_kbd_bell)

        grp_special = QtWidgets.QGroupBox("Special keyboard options")
        vform_special = QtWidgets.QVBoxLayout(grp_special)

        self.chk_toggle_mods = QtWidgets.QCheckBox(
            "ToggleModifiersOnPress — toggles modifier lock on key press")
        self.chk_toggle_mods.toggled.connect(lambda _v: self._update_dirty_indicators())
        vform_special.addWidget(self.chk_toggle_mods)

        self.chk_kick_hotkeys = QtWidgets.QCheckBox(
            "KickHotkeysOnRelease — switches keyboard layout on hotkey release")
        self.chk_kick_hotkeys.toggled.connect(lambda _v: self._update_dirty_indicators())
        vform_special.addWidget(self.chk_kick_hotkeys)

        special_note = QtWidgets.QLabel(
            "Read/applied via xinput, on the master keyboard device's "
            "property.")
        special_note.setWordWrap(True)
        vform_special.addWidget(special_note)

        layout.addWidget(grp_special)
        layout.addStretch(1)
        return outer_tab

    def _on_pointer_field(self, key):
        def handler(value):
            if self._updating_panel:
                return
            dev = self.selected_pointer_device
            if dev and dev in self.pointer_state:
                self.pointer_state[dev][key] = value
                self._update_dirty_indicators()
        return handler

    def _select_pointer_device(self, _text):
        dev = self.cmb_pointer_device.currentData()
        if dev:
            self.selected_pointer_device = dev
            self._sync_pointer_panel()

    def _sync_pointer_panel(self):
        dev = self.selected_pointer_device
        state = self.pointer_state.get(dev, {}) if dev else {}
        self._updating_panel = True
        try:
            if "accel_speed" in state:
                self.spin_pointer_accel.setEnabled(True)
                self.spin_pointer_accel.setValue(state["accel_speed"])
            else:
                self.spin_pointer_accel.setEnabled(False)
            for key, chk in (("natural_scroll", self.chk_pointer_natural_scroll),
                             ("left_handed", self.chk_pointer_left_handed),
                             ("tapping", self.chk_pointer_tapping)):
                if key in state:
                    chk.setEnabled(True)
                    chk.setChecked(state[key])
                else:
                    chk.setEnabled(False)
                    chk.setChecked(False)
        finally:
            self._updating_panel = False

    def _set_kbd(self, key, value):
        if self._updating_panel:
            return
        self.keyboard_state[key] = value
        self._update_dirty_indicators()

    def _sync_keyboard_panel(self):
        self._updating_panel = True
        try:
            s = self.keyboard_state
            self.chk_kbd_repeat.setChecked(s.get("repeat_enabled", True))
            self.spin_kbd_delay.setValue(s.get("repeat_delay", 660))
            self.spin_kbd_rate.setValue(s.get("repeat_rate", 25))
            self.spin_bell_percent.setValue(s.get("bell_percent", 50))
            self.spin_bell_pitch.setValue(s.get("bell_pitch", 400))
            self.spin_bell_duration.setValue(s.get("bell_duration", 100))
        finally:
            self._updating_panel = False

    # ---------------------------------------------------------------- Wallpaper tab

    def _build_wallpaper_tab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)

        self.lbl_wallpaper_status = QtWidgets.QLabel("-")
        self.lbl_wallpaper_status.setWordWrap(True)
        layout.addWidget(self.lbl_wallpaper_status)

        grp_layers = QtWidgets.QGroupBox("Active layers")
        lv = QtWidgets.QVBoxLayout(grp_layers)

        self.tbl_wallpaper = QtWidgets.QTableWidget(0, 7)
        self.tbl_wallpaper.setHorizontalHeaderLabels(
            ["Output", "Desktop", "Mode", "Interval (s)", "Shuffle", "Fade (s)", "Path"])
        self.tbl_wallpaper.horizontalHeader().setStretchLastSection(True)
        no_edit = (QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers if _QT6
                   else QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl_wallpaper.setEditTriggers(no_edit)
        select_rows = (QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows if _QT6
                       else QtWidgets.QAbstractItemView.SelectRows)
        self.tbl_wallpaper.setSelectionBehavior(select_rows)
        self.tbl_wallpaper.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection if _QT6
            else QtWidgets.QAbstractItemView.SingleSelection)
        self.tbl_wallpaper.itemSelectionChanged.connect(self._on_wallpaper_row_selected)
        lv.addWidget(self.tbl_wallpaper)

        row_btns = QtWidgets.QHBoxLayout()
        btn_next = QtWidgets.QPushButton("Next slide")
        btn_next.setToolTip("Advance the selected layer's slideshow now (no-op if it isn't a slideshow).")
        btn_next.clicked.connect(self._on_wallpaper_next)
        row_btns.addWidget(btn_next)
        btn_clear_selected = QtWidgets.QPushButton("Clear selected layer")
        btn_clear_selected.clicked.connect(self._on_wallpaper_clear_selected)
        row_btns.addWidget(btn_clear_selected)
        btn_clear_all = QtWidgets.QPushButton("Clear all layers")
        btn_clear_all.clicked.connect(self._on_wallpaper_clear_all)
        row_btns.addWidget(btn_clear_all)
        btn_refresh = QtWidgets.QPushButton("Refresh")
        btn_refresh.clicked.connect(self._refresh_wallpaper)
        row_btns.addWidget(btn_refresh)
        row_btns.addStretch(1)
        btn_global = QtWidgets.QPushButton("Same wallpaper for everything")
        btn_global.clicked.connect(self._on_wallpaper_set_global)
        row_btns.addWidget(btn_global)
        lv.addLayout(row_btns)

        layout.addWidget(grp_layers, 1)

        grp_set = QtWidgets.QGroupBox("Set / replace a layer")
        outer_set = QtWidgets.QVBoxLayout(grp_set)

        # First few fields packed 2-per-row (2 label:field column pairs) to
        # save vertical space -- 3 rows instead of 6.
        grid = QtWidgets.QGridLayout()

        self.cmb_wp_output = QtWidgets.QComboBox()
        grid.addWidget(QtWidgets.QLabel("Output:"), 0, 0)
        grid.addWidget(self.cmb_wp_output, 0, 1)

        self.cmb_wp_desktop = QtWidgets.QComboBox()
        grid.addWidget(QtWidgets.QLabel("Desktop:"), 0, 2)
        grid.addWidget(self.cmb_wp_desktop, 0, 3)

        self.cmb_wp_mode = QtWidgets.QComboBox()
        self.cmb_wp_mode.addItems(WALLPAPER_MODES)
        grid.addWidget(QtWidgets.QLabel("Mode:"), 1, 0)
        grid.addWidget(self.cmb_wp_mode, 1, 1)

        self.spin_wp_interval = QtWidgets.QSpinBox()
        self.spin_wp_interval.setRange(5, 86400)
        self.spin_wp_interval.setValue(300)
        self.spin_wp_interval.setSuffix(" s")
        grid.addWidget(QtWidgets.QLabel("Slideshow interval:"), 1, 2)
        grid.addWidget(self.spin_wp_interval, 1, 3)

        self.chk_wp_shuffle = QtWidgets.QCheckBox("Random order (instead of alphabetical)")
        grid.addWidget(QtWidgets.QLabel("Slideshow shuffle:"), 2, 0)
        grid.addWidget(self.chk_wp_shuffle, 2, 1)

        self.spin_wp_fade = QtWidgets.QDoubleSpinBox()
        self.spin_wp_fade.setRange(0.0, 5.0)
        self.spin_wp_fade.setSingleStep(0.1)
        self.spin_wp_fade.setDecimals(1)
        self.spin_wp_fade.setValue(1.0)
        self.spin_wp_fade.setSuffix(" s")
        self.spin_wp_fade.setSpecialValueText("Instant (no fade)")
        grid.addWidget(QtWidgets.QLabel("Crossfade duration:"), 2, 2)
        grid.addWidget(self.spin_wp_fade, 2, 3)

        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)
        outer_set.addLayout(grid)

        form = QtWidgets.QFormLayout()
        outer_set.addLayout(form)

        path_row = QtWidgets.QHBoxLayout()
        self.edit_wp_path = QtWidgets.QLineEdit()
        path_row.addWidget(self.edit_wp_path, 1)
        btn_wp_file = QtWidgets.QPushButton("File...")
        btn_wp_file.clicked.connect(self._pick_wallpaper_file)
        path_row.addWidget(btn_wp_file)
        btn_wp_folder = QtWidgets.QPushButton("Folder...")
        btn_wp_folder.clicked.connect(self._pick_wallpaper_folder)
        path_row.addWidget(btn_wp_folder)
        form.addRow("Image or folder:", path_row)

        path_note = QtWidgets.QLabel(
            "A folder is treated as a slideshow (every image file inside "
            "it, in alphabetical or shuffled order); the interval above "
            "only applies in that case.")
        path_note.setWordWrap(True)
        form.addRow(path_note)

        btn_set = QtWidgets.QPushButton("Set layer")
        btn_set.clicked.connect(self._on_wallpaper_set)
        form.addRow(btn_set)

        overlap_note = QtWidgets.QLabel(
            "xisback does not validate overlap between layers: an "
            "output=*/desktop=* layer covering the whole screen at the "
            "same time as a specific output/desktop layer is an "
            "inconsistent setup. When switching schemes (e.g. one global "
            "wallpaper -> one per output), use \"Clear all layers\" "
            "first.")
        overlap_note.setWordWrap(True)
        overlap_note.setStyleSheet(f"color: {SELECT_BORDER};")
        form.addRow(overlap_note)

        layout.addWidget(grp_set)

        grp_actions = QtWidgets.QGroupBox("Click actions (global, any layer)")
        aform = QtWidgets.QFormLayout(grp_actions)

        actions_note = QtWidgets.QLabel(
            "Shell command to run when a wallpaper window is clicked. Runs "
            "detached with XISBACK_OUTPUT/XISBACK_DESKTOP set to the "
            "clicked layer, so e.g. \"xisback --next\" advances whichever "
            "layer was clicked. Leave blank for no action. Double-click is "
            "detected regardless of which button.")
        actions_note.setWordWrap(True)
        aform.addRow(actions_note)

        self.edit_action_left = QtWidgets.QLineEdit()
        self.edit_action_left.setPlaceholderText("e.g. xisback --next")
        aform.addRow("Left click:", self.edit_action_left)

        self.edit_action_right = QtWidgets.QLineEdit()
        aform.addRow("Right click:", self.edit_action_right)

        self.edit_action_middle = QtWidgets.QLineEdit()
        aform.addRow("Middle click:", self.edit_action_middle)

        self.edit_action_double = QtWidgets.QLineEdit()
        aform.addRow("Double-click:", self.edit_action_double)

        btn_actions_save = QtWidgets.QPushButton("Save click actions")
        btn_actions_save.clicked.connect(self._on_actions_save)
        aform.addRow(btn_actions_save)

        layout.addWidget(grp_actions)

        return tab

    def _pick_wallpaper_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Choose an image", self.edit_wp_path.text() or "",
            "Images (*.png *.jpg *.jpeg *.bmp *.webp *.gif *.tiff);;All files (*)")
        if path:
            self.edit_wp_path.setText(path)

    def _pick_wallpaper_folder(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Choose a slideshow folder", self.edit_wp_path.text() or "")
        if path:
            self.edit_wp_path.setText(path)

    def _on_wallpaper_row_selected(self):
        rows = self.tbl_wallpaper.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        output = self.tbl_wallpaper.item(row, 0).text()
        desktop = self.tbl_wallpaper.item(row, 1).text()
        mode = self.tbl_wallpaper.item(row, 2).text()
        interval = self.tbl_wallpaper.item(row, 3).text()
        shuffle = self.tbl_wallpaper.item(row, 4).text()
        fade = self.tbl_wallpaper.item(row, 5).text()
        path = self.tbl_wallpaper.item(row, 6).text()

        idx = self.cmb_wp_output.findData(output)
        self.cmb_wp_output.setCurrentIndex(idx if idx >= 0 else 0)
        idx = self.cmb_wp_desktop.findData(desktop)
        self.cmb_wp_desktop.setCurrentIndex(idx if idx >= 0 else 0)
        if mode in WALLPAPER_MODES:
            self.cmb_wp_mode.setCurrentText(mode)
        try:
            self.spin_wp_interval.setValue(int(float(interval)))
        except ValueError:
            pass
        self.chk_wp_shuffle.setChecked(shuffle == "yes")
        try:
            self.spin_wp_fade.setValue(float(fade))
        except ValueError:
            pass
        self.edit_wp_path.setText(path)

    def _wallpaper_send(self, cmd_line):
        """Logs `cmd_line` (always) and sends it to the daemon unless
        simulation mode is on -- mirrors how xrandr/xinput/xset commands
        are logged elsewhere, even though this isn't a shell command."""
        self._log(f"$ {cmd_line}")
        if self.chk_dry_run.isChecked():
            self._log("(simulation mode: nothing was executed)")
            return None
        try:
            resp = _xisback_send(cmd_line)
        except OSError as e:
            self._log(f"ERROR talking to xisback: {e}")
            QtWidgets.QMessageBox.critical(self, "xisback error", str(e))
            return None
        resp = resp.strip()
        if resp.startswith("ERR"):
            self._log(f"xisback: {resp}")
            QtWidgets.QMessageBox.critical(self, "xisback error", resp)
        else:
            self._log(f"xisback: {resp or 'OK'}")
        return resp

    def _on_wallpaper_set(self):
        path = self.edit_wp_path.text().strip()
        if not path:
            QtWidgets.QMessageBox.warning(
                self, "Missing path", "Choose an image file or folder first.")
            return
        output = self.cmb_wp_output.currentData() or "*"
        desktop = self.cmb_wp_desktop.currentData() or "*"
        mode = self.cmb_wp_mode.currentText()
        interval = self.spin_wp_interval.value()
        shuffle = 1 if self.chk_wp_shuffle.isChecked() else 0
        fade_ms = round(self.spin_wp_fade.value() * 1000)
        self._wallpaper_send(f"SET\t{output}\t{desktop}\t{mode}\t{interval}\t{shuffle}\t{fade_ms}\t{path}")
        self._refresh_wallpaper()

    def _on_wallpaper_next(self):
        rows = self.tbl_wallpaper.selectionModel().selectedRows()
        if not rows:
            QtWidgets.QMessageBox.information(
                self, "No selection", "Select a layer in the table first.")
            return
        row = rows[0].row()
        output = self.tbl_wallpaper.item(row, 0).text()
        desktop = self.tbl_wallpaper.item(row, 1).text()
        self._wallpaper_send(f"NEXT\t{output}\t{desktop}")
        self._refresh_wallpaper()

    def _on_wallpaper_clear_selected(self):
        rows = self.tbl_wallpaper.selectionModel().selectedRows()
        if not rows:
            QtWidgets.QMessageBox.information(
                self, "No selection", "Select a layer in the table first.")
            return
        row = rows[0].row()
        output = self.tbl_wallpaper.item(row, 0).text()
        desktop = self.tbl_wallpaper.item(row, 1).text()
        self._wallpaper_send(f"CLEAR\t{output}\t{desktop}")
        self._refresh_wallpaper()

    def _on_wallpaper_clear_all(self):
        self._wallpaper_send("CLEARALL")
        self._refresh_wallpaper()

    def _on_wallpaper_set_global(self):
        path = self.edit_wp_path.text().strip()
        if not path:
            QtWidgets.QMessageBox.warning(
                self, "Missing path", "Choose an image file or folder first.")
            return
        mode = self.cmb_wp_mode.currentText()
        interval = self.spin_wp_interval.value()
        shuffle = 1 if self.chk_wp_shuffle.isChecked() else 0
        fade_ms = round(self.spin_wp_fade.value() * 1000)
        self._wallpaper_send("CLEARALL")
        self._wallpaper_send(f"SET\t*\t*\t{mode}\t{interval}\t{shuffle}\t{fade_ms}\t{path}")
        self._refresh_wallpaper()

    def _on_actions_save(self):
        left = self.edit_action_left.text()
        right = self.edit_action_right.text()
        middle = self.edit_action_middle.text()
        double = self.edit_action_double.text()
        self._wallpaper_send(f"SETACTIONS\t{left}\t{right}\t{middle}\t{double}")
        self._refresh_wallpaper()

    def _refresh_wallpaper(self):
        self.cmb_wp_output.blockSignals(True)
        self.cmb_wp_output.clear()
        self.cmb_wp_output.addItem("* (all outputs)", "*")
        for out in self.outputs.values():
            if out.connected:
                self.cmb_wp_output.addItem(out.name, out.name)
        self.cmb_wp_output.blockSignals(False)

        self.cmb_wp_desktop.blockSignals(True)
        self.cmb_wp_desktop.clear()
        self.cmb_wp_desktop.addItem("* (all desktops)", "*")
        for i in range(detect_desktop_count()):
            self.cmb_wp_desktop.addItem(f"Desktop {i + 1}", str(i))
        self.cmb_wp_desktop.blockSignals(False)

        layers = xisback_list()
        self.tbl_wallpaper.setRowCount(0)
        if layers is None:
            self.lbl_wallpaper_status.setText(
                "xisback daemon not reachable yet (it will be "
                "auto-started on the next action here).")
            return
        self.lbl_wallpaper_status.setText(
            f"xisback connected — {len(layers)} active layer(s).")
        for layer in layers:
            row = self.tbl_wallpaper.rowCount()
            self.tbl_wallpaper.insertRow(row)
            for col, key in enumerate(("output", "desktop", "mode", "interval", "shuffle", "fade_ms", "path")):
                if key == "shuffle":
                    value = "yes" if layer[key] == "1" else "no"
                elif key == "fade_ms":
                    value = f"{int(layer[key]) / 1000:g}"
                else:
                    value = layer[key]
                self.tbl_wallpaper.setItem(row, col, QtWidgets.QTableWidgetItem(value))

        actions = xisback_get_actions()
        if actions is not None:
            self.edit_action_left.setText(actions["left"])
            self.edit_action_right.setText(actions["right"])
            self.edit_action_middle.setText(actions["middle"])
            self.edit_action_double.setText(actions["double"])

    # ---------------------------------------------------------------- Other tab

    def _build_other_tab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)

        grp_special = QtWidgets.QGroupBox("Primary selection")
        vform_special = QtWidgets.QVBoxLayout(grp_special)

        self.chk_disable_primary_sel = QtWidgets.QCheckBox(
            "DisablePrimarySelection — disables primary selection (middle-click paste)")
        self.chk_disable_primary_sel.toggled.connect(lambda _v: self._update_dirty_indicators())
        vform_special.addWidget(self.chk_disable_primary_sel)

        special_note = QtWidgets.QLabel("Read/applied via xprop (root window property).")
        special_note.setWordWrap(True)
        vform_special.addWidget(special_note)

        layout.addWidget(grp_special)

        grp = QtWidgets.QGroupBox("DPMS (monitor power saving)")
        form = QtWidgets.QFormLayout(grp)

        self.chk_dpms_enabled = QtWidgets.QCheckBox("DPMS enabled")
        self.chk_dpms_enabled.toggled.connect(lambda v: self._set_power("dpms_enabled", v))
        form.addRow(self.chk_dpms_enabled)

        self.spin_dpms_standby = QtWidgets.QSpinBox()
        self.spin_dpms_standby.setRange(0, 36000)
        self.spin_dpms_standby.setSuffix(" s")
        self.spin_dpms_standby.valueChanged.connect(lambda v: self._set_power("dpms_standby", v))
        form.addRow("Standby (0 = disabled):", self.spin_dpms_standby)

        self.spin_dpms_suspend = QtWidgets.QSpinBox()
        self.spin_dpms_suspend.setRange(0, 36000)
        self.spin_dpms_suspend.setSuffix(" s")
        self.spin_dpms_suspend.valueChanged.connect(lambda v: self._set_power("dpms_suspend", v))
        form.addRow("Suspend (0 = disabled):", self.spin_dpms_suspend)

        self.spin_dpms_off = QtWidgets.QSpinBox()
        self.spin_dpms_off.setRange(0, 36000)
        self.spin_dpms_off.setSuffix(" s")
        self.spin_dpms_off.valueChanged.connect(lambda v: self._set_power("dpms_off", v))
        form.addRow("Off (0 = disabled):", self.spin_dpms_off)

        row_dpms_saver = QtWidgets.QHBoxLayout()
        row_dpms_saver.addWidget(grp, 1)

        grp2 = QtWidgets.QGroupBox("Screensaver")
        form2 = QtWidgets.QFormLayout(grp2)

        self.spin_saver_timeout = QtWidgets.QSpinBox()
        self.spin_saver_timeout.setRange(0, 36000)
        self.spin_saver_timeout.setSuffix(" s")
        self.spin_saver_timeout.valueChanged.connect(lambda v: self._set_power("saver_timeout", v))
        form2.addRow("Timeout (0 = disabled):", self.spin_saver_timeout)

        self.spin_saver_cycle = QtWidgets.QSpinBox()
        self.spin_saver_cycle.setRange(0, 36000)
        self.spin_saver_cycle.setSuffix(" s")
        self.spin_saver_cycle.valueChanged.connect(lambda v: self._set_power("saver_cycle", v))
        form2.addRow("Cycle:", self.spin_saver_cycle)

        self.chk_prefer_blanking = QtWidgets.QCheckBox("Prefer blanking the screen")
        self.chk_prefer_blanking.toggled.connect(lambda v: self._set_power("prefer_blanking", v))
        form2.addRow(self.chk_prefer_blanking)

        row_dpms_saver.addWidget(grp2, 1)
        layout.addLayout(row_dpms_saver)

        grp_desktops = QtWidgets.QGroupBox("Virtual desktops")
        form_desktops = QtWidgets.QFormLayout(grp_desktops)

        self.spin_desktop_count = QtWidgets.QSpinBox()
        self.spin_desktop_count.setRange(1, 64)
        self.spin_desktop_count.valueChanged.connect(self._set_desktop_count)
        form_desktops.addRow("Number of desktops:", self.spin_desktop_count)

        self.lbl_desktop_note = QtWidgets.QLabel()
        self.lbl_desktop_note.setWordWrap(True)
        if self.wmctrl_available:
            self.lbl_desktop_note.setText(
                "Applied via `wmctrl -n N` (EWMH _NET_NUMBER_OF_DESKTOPS "
                "request). Depends on the window manager honoring it -- "
                "some WMs (e.g. i3, sway) manage workspaces their own way "
                "and ignore this.")
        else:
            self.lbl_desktop_note.setText(
                "wmctrl not found in PATH -- install it to change the "
                "desktop count from here (the field above is read-only "
                "until then).")
            self.lbl_desktop_note.setStyleSheet(f"color: {SELECT_BORDER};")
            self.spin_desktop_count.setEnabled(False)
        form_desktops.addRow(self.lbl_desktop_note)

        layout.addWidget(grp_desktops)
        layout.addStretch(1)
        return tab

    def _set_power(self, key, value):
        if self._updating_panel:
            return
        self.power_state[key] = value
        self._update_dirty_indicators()

    def _sync_power_panel(self):
        self._updating_panel = True
        try:
            s = self.power_state
            self.chk_dpms_enabled.setChecked(s.get("dpms_enabled", True))
            self.spin_dpms_standby.setValue(s.get("dpms_standby", 0))
            self.spin_dpms_suspend.setValue(s.get("dpms_suspend", 0))
            self.spin_dpms_off.setValue(s.get("dpms_off", 0))
            self.spin_saver_timeout.setValue(s.get("saver_timeout", 0))
            self.spin_saver_cycle.setValue(s.get("saver_cycle", 600))
            self.chk_prefer_blanking.setChecked(s.get("prefer_blanking", True))
            self.spin_desktop_count.setValue(self.desktop_count)
        finally:
            self._updating_panel = False

    def _set_desktop_count(self, value):
        if self._updating_panel:
            return
        self.desktop_count = value
        self._update_dirty_indicators()

    def _refresh_desktop_count(self):
        self.desktop_count = detect_desktop_count()
        self.baseline_desktop_count = self.desktop_count

    # ---------------------------------------------------------------- Permissions tab (xisguard)

    def _build_permissions_tab(self):
        outer_tab = QtWidgets.QWidget()
        outer_layout = QtWidgets.QVBoxLayout(outer_tab)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        outer_layout.addWidget(scroll)

        tab = QtWidgets.QWidget()
        scroll.setWidget(tab)
        layout = QtWidgets.QVBoxLayout(tab)

        self.lbl_xisguard_status = QtWidgets.QLabel("-")
        self.lbl_xisguard_status.setWordWrap(True)
        layout.addWidget(self.lbl_xisguard_status)

        grp_mode = QtWidgets.QGroupBox("Runtime mode")
        form_mode = QtWidgets.QFormLayout(grp_mode)

        self.chk_xg_notify_only = QtWidgets.QCheckBox(
            "Notify only (don't SIGSTOP offending processes)")
        self.chk_xg_notify_only.toggled.connect(
            lambda v: self._set_xisguard("no_pause", 1 if v else 0))
        form_mode.addRow(self.chk_xg_notify_only)

        self.chk_xg_quiet = QtWidgets.QCheckBox(
            "Quiet (no Zenity dialogs; unmatched requests are just denied)")
        self.chk_xg_quiet.toggled.connect(
            lambda v: self._set_xisguard("quiet", 1 if v else 0))
        form_mode.addRow(self.chk_xg_quiet)

        self.chk_xg_always_kill = QtWidgets.QCheckBox(
            "Always kill the offending process (instead of pause/deny)")
        self.chk_xg_always_kill.toggled.connect(
            lambda v: self._set_xisguard("always_kill", 1 if v else 0))
        form_mode.addRow(self.chk_xg_always_kill)

        self.spin_xg_log_level = QtWidgets.QSpinBox()
        self.spin_xg_log_level.setRange(0, 4)
        self.spin_xg_log_level.valueChanged.connect(
            lambda v: self._set_xisguard("log_level", v))
        form_mode.addRow("Log level:", self.spin_xg_log_level)

        layout.addWidget(grp_mode)

        self._xisguard_mode_widgets = [
            self.chk_xg_notify_only, self.chk_xg_quiet,
            self.chk_xg_always_kill, self.spin_xg_log_level,
        ]

        grp_rules = QtWidgets.QGroupBox("Rules (perms.conf)")
        rv = QtWidgets.QVBoxLayout(grp_rules)

        self.tbl_xg_rules = QtWidgets.QTableWidget(0, 3)
        self.tbl_xg_rules.setHorizontalHeaderLabels(["Type", "Action", "Pattern"])
        self.tbl_xg_rules.horizontalHeader().setStretchLastSection(True)
        no_edit = (QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers if _QT6
                   else QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl_xg_rules.setEditTriggers(no_edit)
        select_rows = (QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows if _QT6
                       else QtWidgets.QAbstractItemView.SelectRows)
        self.tbl_xg_rules.setSelectionBehavior(select_rows)
        self.tbl_xg_rules.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection if _QT6
            else QtWidgets.QAbstractItemView.SingleSelection)
        rv.addWidget(self.tbl_xg_rules)

        row_btns = QtWidgets.QHBoxLayout()
        btn_add = QtWidgets.QPushButton("Add rule...")
        btn_add.clicked.connect(self._on_xg_add_rule)
        row_btns.addWidget(btn_add)
        btn_remove = QtWidgets.QPushButton("Remove selected")
        btn_remove.clicked.connect(self._on_xg_remove_rule)
        row_btns.addWidget(btn_remove)
        btn_reload = QtWidgets.QPushButton("Reload from disk")
        btn_reload.clicked.connect(self._on_xg_reload)
        row_btns.addWidget(btn_reload)
        btn_refresh = QtWidgets.QPushButton("Refresh")
        btn_refresh.clicked.connect(self._refresh_permissions)
        row_btns.addWidget(btn_refresh)
        row_btns.addStretch(1)
        rv.addLayout(row_btns)

        layout.addWidget(grp_rules, 1)

        note = QtWidgets.QLabel(
            "Rule changes (Add/Remove/Reload) act immediately on xisguard, "
            "same as the Wallpaper tab -- they aren't part of the staged "
            "Apply. Removing a rule doesn't retract access already granted "
            "to a client in the current session, only future decisions.")
        note.setWordWrap(True)
        layout.addWidget(note)

        layout.addStretch(1)
        return outer_tab

    def _set_xisguard(self, key, value):
        if self._updating_panel:
            return
        self.xisguard_status[key] = value
        self._update_dirty_indicators()

    def _sync_xisguard_panel(self):
        self._updating_panel = True
        try:
            s = self.xisguard_status
            self.chk_xg_notify_only.setChecked(bool(s.get("no_pause", 0)))
            self.chk_xg_quiet.setChecked(bool(s.get("quiet", 0)))
            self.chk_xg_always_kill.setChecked(bool(s.get("always_kill", 0)))
            self.spin_xg_log_level.setValue(s.get("log_level", 0))
            for w in self._xisguard_mode_widgets:
                w.setEnabled(self.xisguard_online)
        finally:
            self._updating_panel = False

    def _refresh_permissions(self):
        status = detect_xisguard_status()
        self.xisguard_online = status is not None
        if status:
            self.xisguard_status = {k: status[k] for k in
                                    ("no_pause", "quiet", "always_kill", "log_level")}
            self.baseline_xisguard_status = dict(self.xisguard_status)
            self.lbl_xisguard_status.setText(
                f"xisguard {status['version']} connected on display :{status['display']}.")
            self._log("xisguard status detected via control socket.")
        else:
            self.xisguard_status = {}
            self.baseline_xisguard_status = {}
            self.lbl_xisguard_status.setText(
                "xisguard not reachable (daemon not running, or its control "
                "socket isn't up yet). Start it manually to manage "
                "permissions from here.")
        self._sync_xisguard_panel()
        self._refresh_xisguard_rules()

    def _refresh_xisguard_rules(self):
        rules = list_xisguard_rules() if self.xisguard_online else None
        self.xisguard_rules = rules or []
        self.tbl_xg_rules.setRowCount(0)
        for rule in self.xisguard_rules:
            row = self.tbl_xg_rules.rowCount()
            self.tbl_xg_rules.insertRow(row)
            for col, key in enumerate(("type", "action", "pattern")):
                self.tbl_xg_rules.setItem(row, col, QtWidgets.QTableWidgetItem(rule[key]))

    def _permissions_send(self, req):
        """Logs `req` (always) and sends it over the xisguard control
        socket unless simulation mode is on -- mirrors _wallpaper_send."""
        args = {k: v for k, v in req.items() if k != "cmd"}
        self._log(f"$ xisguard-ctl {req['cmd']} {args}" if args else f"$ xisguard-ctl {req['cmd']}")
        if self.chk_dry_run.isChecked():
            self._log("(simulation mode: nothing was executed)")
            return None
        try:
            resp = _xisguard_ctl_send(req)
        except OSError as e:
            self._log(f"ERROR talking to xisguard: {e}")
            QtWidgets.QMessageBox.critical(self, "xisguard error", str(e))
            return None
        except ValueError as e:
            self._log(f"ERROR parsing xisguard response: {e}")
            return None
        if not resp.get("ok"):
            self._log(f"xisguard: {resp}")
            QtWidgets.QMessageBox.critical(
                self, "xisguard error", str(resp.get("error", resp)))
        else:
            self._log(f"xisguard: {resp}")
        return resp

    def _on_xg_add_rule(self):
        if not self.xisguard_online:
            QtWidgets.QMessageBox.warning(
                self, "xisguard not reachable", "Refresh once xisguard is running.")
            return
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Add rule")
        form = QtWidgets.QFormLayout(dlg)

        cmb_action = QtWidgets.QComboBox()
        for action, desc in XNOTIFY_ACTIONS:
            cmb_action.addItem(f"{action} -- {desc}", action)
        form.addRow("Action:", cmb_action)

        cmb_type = QtWidgets.QComboBox()
        cmb_type.addItems(["ALLOW", "DENY"])
        form.addRow("Type:", cmb_type)

        edit_pattern = QtWidgets.QLineEdit()
        edit_pattern.setPlaceholderText("/usr/bin/foo, or /usr/bin/foo|--args, or *")
        form.addRow("Pattern:", edit_pattern)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok | QtWidgets.QDialogButtonBox.StandardButton.Cancel
            if _QT6 else QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        form.addRow(buttons)

        if _qexec(dlg) != (QtWidgets.QDialog.DialogCode.Accepted if _QT6 else QtWidgets.QDialog.Accepted):
            return
        pattern = edit_pattern.text().strip()
        if not pattern:
            QtWidgets.QMessageBox.warning(self, "Missing pattern", "Enter an exe pattern first.")
            return
        self._permissions_send({
            "cmd": "ADD_RULE", "action": cmb_action.currentData(),
            "pattern": pattern, "type": cmb_type.currentText(),
        })
        self._refresh_xisguard_rules()

    def _on_xg_remove_rule(self):
        rows = self.tbl_xg_rules.selectionModel().selectedRows()
        if not rows:
            QtWidgets.QMessageBox.information(
                self, "No selection", "Select a rule in the table first.")
            return
        row = rows[0].row()
        rule_type = self.tbl_xg_rules.item(row, 0).text()
        action = self.tbl_xg_rules.item(row, 1).text()
        pattern = self.tbl_xg_rules.item(row, 2).text()
        confirm = QtWidgets.QMessageBox.question(
            self, "Remove rule",
            f"Remove {rule_type} {action} \"{pattern}\"?")
        yes = QtWidgets.QMessageBox.StandardButton.Yes if _QT6 else QtWidgets.QMessageBox.Yes
        if confirm != yes:
            return
        self._permissions_send({
            "cmd": "REMOVE_RULE", "action": action, "pattern": pattern, "type": rule_type,
        })
        self._refresh_xisguard_rules()

    def _on_xg_reload(self):
        self._permissions_send({"cmd": "RELOAD"})
        self._refresh_xisguard_rules()

    def _xisguard_status_diff(self):
        if not self.xisguard_online:
            return None
        fields = {k: v for k, v in self.xisguard_status.items()
                  if self.baseline_xisguard_status.get(k) != v}
        return fields or None

    # ---------------------------------------------------------------- About tab

    def _build_about_tab(self):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)

        grp_app = QtWidgets.QGroupBox("xisconf")
        aform = QtWidgets.QVBoxLayout(grp_app)
        lbl = QtWidgets.QLabel(
            "<b>xisconf</b> — visual runtime configurator Xis, "
            "a XLibre soft fork.<br>Screens (xrandr), pointer/"
            "touchpad/keyboard, wallpaper (via the xisback session "
            "daemon), other settings (DPMS, screensaver, virtual "
            "desktops, XiS special options), and XNOTIFY permissions "
            "(via the xisguard control socket) — all read and applied "
            "with the same commands you'd run by hand in a terminal.")
        lbl.setWordWrap(True)
        aform.addWidget(lbl)
        layout.addWidget(grp_app)

        row = QtWidgets.QHBoxLayout()
        layout.addLayout(row, 1)

        grp_srv = QtWidgets.QGroupBox("Connected X server")
        sform = QtWidgets.QFormLayout(grp_srv)
        self.lbl_srv_name = QtWidgets.QLabel("-")
        self.lbl_srv_vendor = QtWidgets.QLabel("-")
        self.lbl_srv_version = QtWidgets.QLabel("-")
        self.lbl_srv_release = QtWidgets.QLabel("-")
        sform.addRow("Display:", self.lbl_srv_name)
        sform.addRow("Vendor:", self.lbl_srv_vendor)
        sform.addRow("Protocol version:", self.lbl_srv_version)
        sform.addRow("Vendor release:", self.lbl_srv_release)
        row.addWidget(grp_srv, 1)

        grp_ext = QtWidgets.QGroupBox("Active extensions")
        eform = QtWidgets.QVBoxLayout(grp_ext)
        self.list_extensions = QtWidgets.QListWidget()
        eform.addWidget(self.list_extensions)
        ext_note = QtWidgets.QLabel(
            "X11 doesn't allow disabling extensions at runtime — they "
            "are initialized once, at server startup. The only way to "
            "turn one off is to restart Xorg/XLibre/XiS with "
            "\"-extension NAME\" (or disable the module in xorg.conf), "
            "which brings down the whole session. So this list is "
            "informational only.")
        ext_note.setWordWrap(True)
        eform.addWidget(ext_note)
        row.addWidget(grp_ext, 1)

        return tab

    def _refresh_about(self):
        info = detect_server_info()
        self.lbl_srv_name.setText(info["name"])
        self.lbl_srv_vendor.setText(info["vendor"])
        self.lbl_srv_version.setText(info["version"])
        self.lbl_srv_release.setText(info["release"])
        self.list_extensions.clear()
        self.list_extensions.addItems(info["extensions"])

    # ---------------------------------------------------------------- detect/refresh (general)

    def refresh(self):
        self._refresh_screens()
        self._refresh_options()
        self._refresh_pointer()
        self._refresh_keyboard()
        self._refresh_desktop_count()
        self._refresh_power()
        self._refresh_wallpaper()
        self._refresh_permissions()
        self._refresh_about()
        self._update_dirty_indicators()

    # ---------------------------------------------------------------- pending-change tab highlight

    def _screens_dirty(self):
        for name, out in self.outputs.items():
            if not out.connected:
                continue
            baseline = self.baseline_outputs.get(name)
            if baseline is None or out.state_tuple() != baseline.state_tuple():
                return True
        return False

    def _pointer_keyboard_dirty(self):
        if self.chk_toggle_mods.isChecked() != self.baseline_flags.get("toggle_mods_on_press"):
            return True
        if self.chk_kick_hotkeys.isChecked() != self.baseline_flags.get("kick_hotkeys_on_release"):
            return True
        for dev, state in self.pointer_state.items():
            if state != self.baseline_pointer_state.get(dev, {}):
                return True
        if self.keyboard_state != self.baseline_keyboard_state:
            return True
        return False

    def _other_dirty(self):
        if self.chk_disable_primary_sel.isChecked() != self.baseline_flags.get("disable_primary_selection"):
            return True
        if self.power_state != self.baseline_power_state:
            return True
        if self.desktop_count != self.baseline_desktop_count:
            return True
        return False

    def _permissions_dirty(self):
        return self._xisguard_status_diff() is not None

    def _update_dirty_indicators(self):
        dirty_idx = []
        if self._screens_dirty():
            dirty_idx.append(self._tab_index_screens)
        if self._pointer_keyboard_dirty():
            dirty_idx.append(self._tab_index_pointer_kbd)
        if self._other_dirty():
            dirty_idx.append(self._tab_index_other)
        if self._permissions_dirty():
            dirty_idx.append(self._tab_index_permissions)
        rules = "\n".join(
            f"QTabBar::tab:nth-child({idx + 1}) {{ font: italic bold; color: %s; }}" % SELECT_BORDER
            for idx in dirty_idx)
        self.tabs.tabBar().setStyleSheet(rules)

        if not hasattr(self, "lbl_pending"):
            return
        if dirty_idx:
            names = ", ".join(self.tabs.tabText(idx) for idx in dirty_idx)
            self.lbl_pending.setText(f"Pending changes in: {names}")
        else:
            self.lbl_pending.setText("No pending changes.")

    def _refresh_screens(self):
        try:
            self.outputs = detect()
        except subprocess.CalledProcessError as e:
            self._log(f"Failed to run xrandr: {e}")
            return
        except FileNotFoundError:
            self._log("xrandr not found in PATH.")
            return

        enabled = [o for o in self.outputs.values() if o.connected and o.enabled]
        min_x = min((o.x for o in enabled), default=0)
        min_y = min((o.y for o in enabled), default=0)
        max_x = max((o.x + o.rotated_size()[0] for o in enabled), default=1920)
        max_y = max((o.y + o.rotated_size()[1] for o in enabled), default=1080)
        span_x = max(max_x - min_x, 1)
        span_y = max(max_y - min_y, 1)
        self.world_origin = (min_x, min_y)
        self.px_per_unit = min(900 / span_x, 500 / span_y, 0.25)

        self._rebuild_scene()
        self._rebuild_monitor_combo()

        if self.outputs:
            first_connected = next(
                (o.name for o in self.outputs.values() if o.connected), None)
            self.select(first_connected)

        self.baseline_outputs = copy.deepcopy(self.outputs)
        self._log("Screens detected via xrandr.")

    def _refresh_options(self):
        flags, kbd, warnings = detect_special_options()
        self._keyboard_device = kbd

        for chk, key in ((self.chk_toggle_mods, "toggle_mods_on_press"),
                         (self.chk_kick_hotkeys, "kick_hotkeys_on_release"),
                         (self.chk_disable_primary_sel, "disable_primary_selection")):
            chk.blockSignals(True)
            chk.setChecked(flags[key])
            chk.blockSignals(False)

        self.baseline_flags = dict(flags)
        for w in warnings:
            self._log(f"Warning: {w}")
        self._log(f"Special options detected via xinput/xprop (keyboard: {kbd}).")

    def _refresh_pointer(self):
        self.pointer_devices = list_pointer_devices()
        self.pointer_state = {d: detect_pointer_device(d) for d in self.pointer_devices}
        self.baseline_pointer_state = copy.deepcopy(self.pointer_state)

        self.cmb_pointer_device.blockSignals(True)
        self.cmb_pointer_device.clear()
        for d in self.pointer_devices:
            self.cmb_pointer_device.addItem(d, d)
        self.cmb_pointer_device.blockSignals(False)

        if self.pointer_devices:
            self.selected_pointer_device = self.pointer_devices[0]
            self.cmb_pointer_device.setCurrentIndex(0)
        else:
            self.selected_pointer_device = None
        self._sync_pointer_panel()
        self._log(f"Pointer devices detected: {len(self.pointer_devices)}.")

    def _refresh_keyboard(self):
        self.keyboard_state = detect_keyboard_xset()
        self.baseline_keyboard_state = dict(self.keyboard_state)
        self._sync_keyboard_panel()
        self._log("Keyboard (repeat/bell) detected via xset.")

    def _refresh_power(self):
        self.power_state = detect_power_xset()
        self.baseline_power_state = dict(self.power_state)
        self._sync_power_panel()
        self._log("DPMS/screensaver detected via xset.")

    def _rebuild_scene(self):
        self.scene.clear()
        self.items = {}
        ox, oy = self.world_origin
        for out in self.outputs.values():
            if not (out.connected and out.enabled):
                continue
            item = OutputItem(out, self.px_per_unit, dpi_visual=self.chk_dpi_visual.isChecked())
            item.setPos((out.x - ox) * self.px_per_unit,
                        (out.y - oy) * self.px_per_unit)
            item.positionChanged.connect(self._on_item_moved)
            item.clicked.connect(self.select)
            self.scene.addItem(item)
            self.items[out.name] = item
            if out.name == self.selected:
                item.setSelected(True)
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-60, -60, 60, 60))
        self._update_dirty_indicators()
        self.view.fitInView(self.scene.sceneRect(), QtCore.Qt.AspectRatioMode.KeepAspectRatio
                            if _QT6 else QtCore.Qt.KeepAspectRatio)

    def _rebuild_monitor_combo(self):
        self.cmb_monitor.blockSignals(True)
        self.cmb_monitor.clear()
        for out in self.outputs.values():
            suffix = "" if out.connected else "  (disconnected)"
            self.cmb_monitor.addItem(out.name + suffix, out.name)
        self.cmb_monitor.blockSignals(False)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.scene.sceneRect().isValid():
            self.view.fitInView(self.scene.sceneRect(), QtCore.Qt.AspectRatioMode.KeepAspectRatio
                                if _QT6 else QtCore.Qt.KeepAspectRatio)

    # ---------------------------------------------------------------- selection (Screens)

    def _select_from_combo(self, _text):
        name = self.cmb_monitor.currentData()
        if name:
            self.select(name)

    def select(self, name):
        if not name or name not in self.outputs:
            return
        self.selected = name
        for n, item in self.items.items():
            item.setSelected(n == name)
        idx = self.cmb_monitor.findData(name)
        if idx >= 0:
            self.cmb_monitor.blockSignals(True)
            self.cmb_monitor.setCurrentIndex(idx)
            self.cmb_monitor.blockSignals(False)
        self._sync_panel()

    def _sync_panel(self):
        out = self.outputs.get(self.selected)
        if not out:
            return
        self._updating_panel = True
        try:
            self.lbl_status.setText("Connected" if out.connected else "Disconnected")
            for w in self._panel_widgets:
                w.setEnabled(out.connected)

            self.chk_enabled.setChecked(out.enabled)
            self.chk_primary.setChecked(out.primary)

            self.cmb_resolution.clear()
            self.cmb_resolution.addItems(out.mode_names())
            if out.current_mode:
                idx = self.cmb_resolution.findText(out.current_mode)
                if idx >= 0:
                    self.cmb_resolution.setCurrentIndex(idx)

            self._fill_rates(out)

            self.cmb_rotation.setCurrentText(ROTATION_LABELS.get(out.rotation, "Normal"))

            self.cmb_mirror.clear()
            self.cmb_mirror.addItem("None (independent)", None)
            for other in self.outputs.values():
                if other.name != out.name and other.connected:
                    self.cmb_mirror.addItem(other.name, other.name)
            idx = self.cmb_mirror.findData(out.mirror_of)
            self.cmb_mirror.setCurrentIndex(idx if idx >= 0 else 0)

            self.lbl_pos.setText(f"{out.x}, {out.y}")

            self.spin_dpi.setValue(out.dpi or 96)
            self.lbl_dpi_factor.setText(f"≈ {(out.dpi or 96) / 96:.2f}x")

            self.spin_scale.setValue(out.scale_x or 1.0)

            self._rebuild_extra_props(out)

            movable = out.enabled and not out.mirror_of
            item = self.items.get(out.name)
            if item:
                item.setFlag(_movable(), movable)
        finally:
            self._updating_panel = False

    def _fill_rates(self, out):
        self.cmb_rate.blockSignals(True)
        self.cmb_rate.clear()
        rates = out.rates_for(out.current_mode) if out.current_mode else []
        for rate, _cur, _pref in rates:
            self.cmb_rate.addItem(f"{rate} Hz", rate)
        if out.current_rate:
            idx = self.cmb_rate.findData(out.current_rate)
            if idx >= 0:
                self.cmb_rate.setCurrentIndex(idx)
        self.cmb_rate.blockSignals(False)

    # ---------------------------------------------------------------- panel callbacks (Screens)

    def _current(self):
        return self.outputs.get(self.selected)

    def _on_enabled(self, checked):
        if self._updating_panel:
            return
        out = self._current()
        if not out:
            return
        out.enabled = checked
        self._rebuild_scene()

    def _on_primary(self, checked):
        if self._updating_panel:
            return
        out = self._current()
        if not out:
            return
        out.primary = checked
        if checked:
            for other in self.outputs.values():
                if other.name != out.name:
                    other.primary = False
        self._rebuild_scene()

    def _on_resolution(self, text):
        if self._updating_panel or not text:
            return
        out = self._current()
        if not out:
            return
        out.current_mode = text
        rates = out.rates_for(text)
        out.current_rate = rates[0][0] if rates else None
        w, h = (int(v) for v in text.split("x"))
        out.width, out.height = w, h
        self._fill_rates(out)
        self._rebuild_scene()

    def _on_rate(self, _text):
        if self._updating_panel:
            return
        out = self._current()
        if not out:
            return
        rate = self.cmb_rate.currentData()
        if rate:
            out.current_rate = rate
            self._update_dirty_indicators()

    def _on_rotation(self, text):
        if self._updating_panel:
            return
        out = self._current()
        if not out:
            return
        out.rotation = ROTATION_LABELS_REV.get(text, "normal")
        self._rebuild_scene()

    def _on_mirror(self, _text):
        if self._updating_panel:
            return
        out = self._current()
        if not out:
            return
        out.mirror_of = self.cmb_mirror.currentData()
        if out.mirror_of and out.mirror_of in self.outputs:
            target = self.outputs[out.mirror_of]
            out.x, out.y = target.x, target.y
        self._rebuild_scene()

    def _on_dpi(self, value):
        self.lbl_dpi_factor.setText(f"≈ {value / 96:.2f}x")
        self.lbl_dpi_warning.setVisible(value < 96)
        if self._updating_panel:
            return
        out = self._current()
        if out:
            out.dpi = value
            self._rebuild_scene()

    def _on_scale(self, value):
        if self._updating_panel:
            return
        out = self._current()
        if out:
            out.scale_x = value
            out.scale_y = value
            self._rebuild_scene()

    def _on_item_moved(self):
        out = self._current()
        item = self.items.get(self.selected) if out else None
        if not out or not item:
            return
        ox, oy = self.world_origin
        out.x = ox + round(item.pos().x() / self.px_per_unit)
        out.y = oy + round(item.pos().y() / self.px_per_unit)
        self.lbl_pos.setText(f"{out.x}, {out.y}")
        self._update_dirty_indicators()

    # ---------------------------------------------------------------- diff + apply

    def _normalize_low_dpi(self):
        """DPI < 96 isn't applied as the DPI property (outside the
        intended domain -- see AutoDPI/Tier1 SCALE): converts to DPI 96 +
        equivalent --scale (factor's inverse) before building the
        command."""
        changed = False
        for out in self.outputs.values():
            if out.connected and out.enabled and out.dpi and out.dpi < 96:
                factor = out.dpi / 96.0
                inverse = round(1.0 / factor, 4)
                self._log(f"Warning: {out.name} had DPI {out.dpi} (<96) — "
                          f"converted to DPI 96 + --scale {inverse}x{inverse} "
                          "(DPI below 96 is never applied).")
                out.dpi = 96
                out.scale_x = inverse
                out.scale_y = inverse
                changed = True
        if changed:
            self._sync_panel()
            self._rebuild_scene()

    def _build_changed_screen_args(self):
        """Only emits --output NAME <fields that changed> for outputs
        whose state (compared to the baseline from the last detect/apply)
        actually changed -- e.g. if only the refresh rate changed, the
        block is --output NAME --rate X, not the output's whole
        description."""
        args = []
        changed_names = []
        for name, out in self.outputs.items():
            if not out.connected:
                continue
            baseline = self.baseline_outputs.get(name)
            if baseline is None:
                block = _output_args(out)
            elif out.state_tuple() != baseline.state_tuple():
                block = _output_diff_args(out, baseline)
            else:
                continue
            if block:
                args += block
                changed_names.append(name)
        if changed_names:
            self._log(f"Screens changed: {', '.join(changed_names)}")
        return args

    def _build_changed_prop_commands(self):
        """xinput/xprop commands for the flags that changed."""
        current = {
            "toggle_mods_on_press": self.chk_toggle_mods.isChecked(),
            "kick_hotkeys_on_release": self.chk_kick_hotkeys.isChecked(),
            "disable_primary_selection": self.chk_disable_primary_sel.isChecked(),
        }
        cmds = []
        for key, value in current.items():
            if self.baseline_flags.get(key) != value:
                argv = build_special_option_command(self._keyboard_device, key, value)
                cmds.append((SPECIAL_OPTION_LABELS[key], argv))
        return cmds

    def _build_changed_pointer_commands(self):
        cmds = []
        for dev, state in self.pointer_state.items():
            baseline = self.baseline_pointer_state.get(dev, {})
            for key, value in state.items():
                if baseline.get(key) != value:
                    argv = build_pointer_command(dev, key, value)
                    cmds.append((f"{POINTER_PROP_LABELS[key]} ({dev})", argv))
        return cmds

    def apply(self):
        self._normalize_low_dpi()

        screen_args = self._build_changed_screen_args()
        prop_cmds = self._build_changed_prop_commands()
        pointer_cmds = self._build_changed_pointer_commands()
        keyboard_cmds = build_keyboard_commands(self.keyboard_state, self.baseline_keyboard_state)
        power_cmds = build_power_commands(self.power_state, self.baseline_power_state)
        desktop_cmds = []
        if self.desktop_count != self.baseline_desktop_count:
            desktop_cmds.append(("Number of desktops", build_desktop_count_command(self.desktop_count)))
        xisguard_status_change = self._xisguard_status_diff()

        all_prop_cmds = prop_cmds + pointer_cmds + keyboard_cmds + power_cmds + desktop_cmds

        if not screen_args and not all_prop_cmds and not xisguard_status_change:
            self._log("Nothing to apply (no pending changes).")
            return

        dry = self.chk_dry_run.isChecked()

        if screen_args:
            cmd_str = shlex.join(["xrandr"] + screen_args)
            self._log(f"$ {cmd_str}")
            if not dry:
                result = subprocess.run(["xrandr"] + screen_args,
                                        capture_output=True, text=True)
                if result.returncode != 0:
                    self._log(f"ERROR (code {result.returncode}): {result.stderr.strip()}")
                    QtWidgets.QMessageBox.critical(
                        self, "Failed to apply layout",
                        result.stderr.strip() or "unknown error")
                else:
                    self._log("Layout applied successfully.")

        for desc, argv in all_prop_cmds:
            self._log(f"$ {shlex.join(argv)}")
            if not dry:
                try:
                    result = subprocess.run(argv, capture_output=True, text=True)
                except FileNotFoundError:
                    self._log(f"ERROR applying {desc}: {argv[0]} not found in PATH.")
                    continue
                if result.returncode != 0:
                    self._log(f"ERROR applying {desc}: {result.stderr.strip()}")
                else:
                    self._log(f"{desc}: applied.")

        if xisguard_status_change:
            self._permissions_send({"cmd": "SET_STATUS", **xisguard_status_change})

        if dry:
            self._log("(simulation mode: nothing was executed)")
        else:
            self.refresh()

    def _log(self, text):
        self.log.appendPlainText(text)
        self._last_log_line = text
        self._set_log_bar_text()

    def _set_log_bar_text(self):
        if self.btn_log_toggle.isChecked():
            self.btn_log_toggle.setText("▾ Command log (click to hide)")
            return
        last = self._last_log_line or "no commands logged yet"
        preview = last if len(last) <= 90 else last[:87] + "..."
        self.btn_log_toggle.setText(f"▸ {preview}")

    def _toggle_log(self, checked):
        self.log.setVisible(checked)
        self._set_log_bar_text()


# ══════════════════════════════ entry point ══════════════════════════════

def main():
    if "--self-test" in sys.argv:
        outs = detect()
        for o in outs.values():
            extra = f" extra={list(o.extra_props_meta)}" if o.extra_props_meta else ""
            print(f"{o.name}: connected={o.connected} enabled={o.enabled} "
                  f"{o.width}x{o.height}+{o.x}+{o.y} rot={o.rotation} "
                  f"dpi={o.dpi} scale=({o.scale_x},{o.scale_y}) "
                  f"primary={o.primary} modes={len(o.modes)}{extra}")
        print()
        print(shlex.join(["xrandr"] + build_command(outs)))

        flags, kbd, warnings = detect_special_options()
        print()
        print(f"Master keyboard: {kbd}")
        for k, v in flags.items():
            print(f"{SPECIAL_OPTION_LABELS[k]}: {v}")
        for w in warnings:
            print(f"warning: {w}")

        print()
        for dev in list_pointer_devices():
            print(f"Pointer '{dev}': {detect_pointer_device(dev)}")

        print()
        print("Keyboard (repeat/bell):", detect_keyboard_xset())
        print("Power/screen (DPMS/saver):", detect_power_xset())

        print()
        info = detect_server_info()
        print(f"Server: {info['vendor']} {info['release']} "
              f"(protocol {info['version']}), display {info['name']}")
        print(f"Extensions ({len(info['extensions'])}): {', '.join(info['extensions'])}")
        return 0

    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow(dry_run="--dry-run" in sys.argv)
    win.show()
    return _qexec(app)


if __name__ == "__main__":
    sys.exit(main())
