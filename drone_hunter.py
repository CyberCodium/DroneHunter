#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════╗
║              DroneHunter  ·  Sistema de Detección RF               ║
║                       Version 1.0.0                                 ║
╠══════════════════════════════════════════════════════════════════════╣
║  Copyright (c) 2026 E.B.G — All Rights Reserved                    ║
║                                                                      ║
║  Licencia de Uso Personal — Personal Use License                    ║
║  ─────────────────────────────────────────────────                  ║
║  ✔  Uso personal, educativo e investigación NO comercial: LIBRE     ║
║  ✘  Uso comercial, empresarial o con fines de lucro: PROHIBIDO      ║
║  ✘  Uso gubernamental, institucional o de administración            ║
║     pública: PROHIBIDO                                              ║
║  ✘  Uso militar, policial, de inteligencia o defensa: PROHIBIDO     ║
║     Todo uso anterior requiere autorización expresa y por          ║
║     escrito del autor (E.B.G).                                      ║
║                                                                      ║
║  Esto incluye, sin limitación: empresas privadas, organismos        ║
║  públicos, fuerzas armadas, agencias de seguridad y cualquier       ║
║  entidad gubernamental a cualquier nivel (local, regional,         ║
║  nacional o supranacional).                                         ║
║                                                                      ║
║  Para solicitar permisos contacta al autor:                         ║
║  ►  hacklabosofficial@proton.me                                       ║
╚══════════════════════════════════════════════════════════════════════╝

Detección automática de drones basada en análisis de espectro RF.
Clasifica firmas de señal en tiempo real y emite alertas acústicas
graduadas por nivel de amenaza.

Protocolo detectados: DJI OcuSync 2/3, DJI O3/FPV-HD, ExpressLRS,
TBS Crossfire, FrSky, FlySky, Spektrum, FPV analógico 5.8/1.3/1.2 GHz,
LoRa/SiK telemetría, Wi-Fi 2.4/5 GHz, RC legacy 433/868/915 MHz.

Uso:
    python3 drone_hunter.py

Dependencias:
    pip install PyQt5 pyqtgraph numpy

Opcional (hardware HackRF One):
    pip install HackRF
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import wave
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import numpy as np
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog,
    QFormLayout, QFrame, QGroupBox, QHBoxLayout, QHeaderView, QLabel,
    QMainWindow, QMessageBox, QProgressBar, QPushButton,
    QSlider, QSpinBox, QSplitter, QTableWidget, QTableWidgetItem,
    QTextEdit, QVBoxLayout, QWidget,
)
import pyqtgraph as pg

# ──────────────────────────────────────────────────────────────────────────────
#  Optional HackRF driver
# ──────────────────────────────────────────────────────────────────────────────
try:
    from hackrf import HackRF  # type: ignore
    HACKRF_AVAILABLE = True
except ImportError:
    HACKRF_AVAILABLE = False

# ──────────────────────────────────────────────────────────────────────────────
#  Version / authorship
# ──────────────────────────────────────────────────────────────────────────────
__version__ = "1.0.0"
__author__  = "E.B.G"
__license__ = "Personal Use Only — Commercial, governmental or business use requires written permission from E.B.G"
__year__    = "2026"

# ──────────────────────────────────────────────────────────────────────────────
#  RF protocol database
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Protocol:
    name:      str
    freq_mhz:  float
    bw_mhz:    float
    category:  str    # drone_ctrl | fpv_video | telemetry | wifi
    color:     str
    power:     float  # simulation level 0–1
    notes:     str = ""


PROTOCOL_DB: list[Protocol] = [
    # ── Wi-Fi 2.4 GHz ────────────────────────────────────────────────────────
    Protocol("Wi-Fi CH1  (2412)",   2412.0, 22.0, "wifi",       "#3b82f6", 0.65, "802.11b/g/n"),
    Protocol("Wi-Fi CH6  (2437)",   2437.0, 22.0, "wifi",       "#3b82f6", 0.55, "802.11b/g/n"),
    Protocol("Wi-Fi CH11 (2462)",   2462.0, 22.0, "wifi",       "#3b82f6", 0.70, "802.11b/g/n"),
    # ── DJI OcuSync / O3 control links ───────────────────────────────────────
    Protocol("DJI OcuSync 2.0",     2440.0, 10.0, "drone_ctrl", "#f59e0b", 0.80, "DJI Air 2 / Mini 2"),
    Protocol("DJI OcuSync 3.0",     2408.0,  8.0, "drone_ctrl", "#f59e0b", 0.85, "DJI Mini 3 Pro / Mavic 3"),
    Protocol("DJI O3 5.8G",         5840.0, 20.0, "drone_ctrl", "#f59e0b", 0.83, "DJI Avata / Goggles 2"),
    # ── DJI FPV HD video ─────────────────────────────────────────────────────
    Protocol("DJI FPV HD Link",     5785.0, 20.0, "fpv_video",  "#f59e0b", 0.85, "DJI FPV Goggles"),
    # ── Generic RC 2.4 GHz ───────────────────────────────────────────────────
    Protocol("FrSky FHSS 2.4G",    2450.0,  1.0, "drone_ctrl", "#a78bfa", 0.70, "Taranis / Horus"),
    Protocol("FlySky AFHDS2A",      2420.0,  1.0, "drone_ctrl", "#a78bfa", 0.65),
    Protocol("Spektrum DSM2",       2424.0,  1.0, "drone_ctrl", "#a78bfa", 0.60),
    Protocol("Spektrum DSMX",       2432.0,  1.0, "drone_ctrl", "#a78bfa", 0.60),
    # ── Wi-Fi 5 GHz ──────────────────────────────────────────────────────────
    Protocol("Wi-Fi 5G CH36",       5180.0, 40.0, "wifi",       "#60a5fa", 0.50, "802.11a/n/ac"),
    Protocol("Wi-Fi 5G CH100",      5500.0, 40.0, "wifi",       "#60a5fa", 0.45),
    Protocol("Wi-Fi 5G CH149",      5745.0, 40.0, "wifi",       "#60a5fa", 0.50),
    # ── 5.8 GHz Analog FPV ───────────────────────────────────────────────────
    Protocol("FPV A1 (5658 MHz)",   5658.0,  8.0, "fpv_video",  "#ec4899", 0.90, "Banda A"),
    Protocol("FPV A2 (5695 MHz)",   5695.0,  8.0, "fpv_video",  "#ec4899", 0.85),
    Protocol("FPV F2 (5760 MHz)",   5760.0,  8.0, "fpv_video",  "#f472b6", 0.88, "Banda F / Fatshark"),
    Protocol("FPV F4 (5800 MHz)",   5800.0,  8.0, "fpv_video",  "#f472b6", 0.92, "Más común"),
    Protocol("FPV R7 (5880 MHz)",   5880.0,  8.0, "fpv_video",  "#ec4899", 0.87, "RaceBand"),
    # ── 868 / 915 MHz RC links ───────────────────────────────────────────────
    Protocol("TBS Crossfire 868",    868.0,  0.5, "drone_ctrl", "#10b981", 0.80, "Team BlackSheep EU"),
    Protocol("ExpressLRS 868",       869.0,  0.5, "drone_ctrl", "#34d399", 0.82, "ELRS FHSS EU"),
    Protocol("TBS Crossfire 915",    915.0,  0.5, "drone_ctrl", "#10b981", 0.80, "North America"),
    Protocol("ExpressLRS 915",       916.0,  0.5, "drone_ctrl", "#34d399", 0.82, "ELRS FHSS NA"),
    Protocol("LoRa MAVLink 868",     868.5,  0.5, "telemetry",  "#22d3ee", 0.70, "ArduPilot/PX4 telemetría"),
    Protocol("LoRa MAVLink 915",     915.5,  0.5, "telemetry",  "#22d3ee", 0.70),
    # ── 433 MHz long-range ───────────────────────────────────────────────────
    Protocol("SiK Radio 433",        433.0,  1.0, "telemetry",  "#22d3ee", 0.75, "3DR / RFD900"),
    Protocol("ExpressLRS 433",       433.5,  0.5, "drone_ctrl", "#34d399", 0.72, "ELRS 433 MHz"),
    # ── 1.2 – 1.3 GHz long-range FPV ────────────────────────────────────────
    Protocol("FPV 1.3G (1280)",     1280.0,  6.0, "fpv_video",  "#f472b6", 0.80, "Largo alcance"),
    Protocol("FPV 1.3G (1320)",     1320.0,  6.0, "fpv_video",  "#f472b6", 0.76),
]

BAND_PRESETS = [
    ("433 MHz  · ELRS / SiK",       433.0),
    ("868 MHz  · Crossfire / LoRa", 868.0),
    ("915 MHz  · ExpressLRS NA",    915.0),
    ("1.3 GHz  · FPV largo alcance",1280.0),
    ("2.4 GHz  · OcuSync / Wi-Fi", 2440.0),
    ("5.8 GHz  · FPV / DJI O3",    5800.0),
]

SPAN_OPTIONS_MHZ = [1.0, 2.0, 5.0, 10.0, 20.0, 40.0, 80.0]

# ──────────────────────────────────────────────────────────────────────────────
#  Threat model
# ──────────────────────────────────────────────────────────────────────────────

class ThreatLevel(Enum):
    NONE     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


THREAT_CFG = {
    ThreatLevel.NONE: {
        "label":  "SIN AMENAZA",
        "sub":    "Espectro limpio — ningún drone detectado",
        "bg":     "#0d1117",
        "fg":     "#8b949e",
        "border": "#21262d",
        "sound":  None,
    },
    ThreatLevel.LOW: {
        "label":  "⚠  AMENAZA BAJA",
        "sub":    "Señal de RF compatible con drone — monitorizando",
        "bg":     "#0f2318",
        "fg":     "#3fb950",
        "border": "#3fb950",
        "sound":  "single",
    },
    ThreatLevel.MEDIUM: {
        "label":  "⚠  AMENAZA MEDIA",
        "sub":    "Señal de drone confirmada con moderada confianza",
        "bg":     "#231c05",
        "fg":     "#e3b341",
        "border": "#e3b341",
        "sound":  "double",
    },
    ThreatLevel.HIGH: {
        "label":  "🔴  AMENAZA ALTA",
        "sub":    "Drone casi seguro — link de control + vídeo detectados",
        "bg":     "#3a1515",
        "fg":     "#f85149",
        "border": "#f85149",
        "sound":  "rapid",
    },
    ThreatLevel.CRITICAL: {
        "label":  "🚨  AMENAZA CRÍTICA",
        "sub":    "Drone identificado con alta certeza — múltiples señales activas",
        "bg":     "#7a0000",
        "fg":     "#ffffff",
        "border": "#ff2222",
        "sound":  "siren",
    },
}


@dataclass
class ThreatReport:
    level:      ThreatLevel
    confidence: float             # 0.0 – 1.0
    drone_type: str
    signals:    list              # list[DetectedSignal]
    timestamp:  str = field(
        default_factory=lambda: datetime.datetime.now().strftime("%H:%M:%S")
    )

# ──────────────────────────────────────────────────────────────────────────────
#  Drone classifier
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectedSignal:
    freq_mhz:  float
    power:     float
    bw_mhz:    float
    label:     str
    category:  str
    color:     str
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now().strftime("%H:%M:%S")
    )


class DroneClassifier:
    """
    Motor de clasificación de drones por firma RF multi-señal.

    Algoritmo:
    1.  Acumula un contador de persistencia por señal detectada.
    2.  Solo puntúa señales vistas durante al menos N frames consecutivos
        (evita falsas alarmas por picos de ruido).
    3.  Evalúa "huellas de drone" conocidas:
        - DJI: OcuSync + vídeo HD → confianza alta
        - FPV Racing: ELRS/Crossfire + FPV analógico → confianza alta
        - Autónomo: telemetría + control → confianza media-alta
        - Control solo / FPV solo → confianza baja-media
    4.  Bonus por múltiples señales simultáneas.
    """

    def __init__(self, persistence: int = 6) -> None:
        self._persistence = persistence
        self._counts: dict[str, int] = {}

    def reset(self) -> None:
        self._counts.clear()

    @property
    def persistence(self) -> int:
        return self._persistence

    @persistence.setter
    def persistence(self, v: int) -> None:
        self._persistence = max(1, int(v))

    def update(self, signals: list[DetectedSignal]) -> ThreatReport:
        current = {s.label for s in signals}
        new_counts: dict[str, int] = {}
        for lbl, n in self._counts.items():
            if lbl in current:
                new_counts[lbl] = n + 1
        for lbl in current:
            if lbl not in new_counts:
                new_counts[lbl] = 1
        self._counts = new_counts

        persistent = [
            s for s in signals
            if self._counts.get(s.label, 0) >= self._persistence
        ]

        confidence, dtype, dsigs = self._score(persistent)

        if confidence >= 0.85:
            level = ThreatLevel.CRITICAL
        elif confidence >= 0.70:
            level = ThreatLevel.HIGH
        elif confidence >= 0.50:
            level = ThreatLevel.MEDIUM
        elif confidence >= 0.25:
            level = ThreatLevel.LOW
        else:
            level = ThreatLevel.NONE

        return ThreatReport(
            level      = level,
            confidence = round(confidence, 3),
            drone_type = dtype,
            signals    = dsigs,
        )

    # ── Internal scoring ──────────────────────────────────────────────────────

    def _score(
        self, sigs: list[DetectedSignal]
    ) -> tuple[float, str, list[DetectedSignal]]:

        ctrl  = [s for s in sigs if s.category == "drone_ctrl"]
        fpv   = [s for s in sigs if s.category == "fpv_video"]
        telem = [s for s in sigs if s.category == "telemetry"]

        if not ctrl and not fpv and not telem:
            return 0.0, "Sin amenaza detectada", []

        best_score = 0.0
        best_type  = "Drone desconocido"
        best_sigs: list[DetectedSignal] = []

        def _update(score, dtype, dsigs):
            nonlocal best_score, best_type, best_sigs
            if score > best_score:
                best_score, best_type, best_sigs = score, dtype, list(dsigs)

        # ── DJI OcuSync / O3 ─────────────────────────────────────────────────
        dji_ctrl = [s for s in ctrl if "DJI" in s.label or "OcuSync" in s.label]
        dji_fpv  = [s for s in fpv  if "DJI" in s.label]

        if dji_ctrl:
            sc, st, ss = 0.65, "DJI Consumer (OcuSync)", list(dji_ctrl)
            if dji_fpv:
                sc = 0.93
                is_avata = any("FPV" in s.label or "O3" in s.label for s in dji_fpv)
                st = "DJI Avata / FPV" if is_avata else "DJI Mavic / Mini + HD"
                ss.extend(dji_fpv)
            elif fpv:
                sc = 0.78
                st = "DJI Drone + FPV analógico"
                ss.extend(fpv[:2])
            _update(sc, st, ss)

        # ── ExpressLRS / TBS Crossfire ────────────────────────────────────────
        elrs = [
            s for s in ctrl
            if any(k in s.label for k in ["ExpressLRS", "Crossfire", "ELRS"])
        ]
        if elrs:
            sc, st, ss = 0.55, "Control largo alcance (ELRS/Crossfire)", list(elrs)
            non_dji_fpv = [s for s in fpv if "DJI" not in s.label]
            if non_dji_fpv:
                sc = 0.87
                st = "Drone FPV Racing (ELRS/Crossfire + Analógico)"
                ss.extend(non_dji_fpv[:2])
            if telem:
                sc = max(sc, 0.82)
                st += " + Telemetría"
                ss.extend(telem[:1])
            _update(sc, st, ss)

        # ── Generic RC 2.4 GHz (FrSky / FlySky / Spektrum) ───────────────────
        used = set(id(s) for s in best_sigs)
        generic = [
            s for s in ctrl
            if id(s) not in used
            and "DJI" not in s.label
            and not any(k in s.label for k in ["ExpressLRS", "Crossfire"])
        ]
        if generic:
            sc, st, ss = 0.45, f"RC 2.4 GHz ({generic[0].label})", [generic[0]]
            non_dji_fpv = [s for s in fpv if "DJI" not in s.label]
            if non_dji_fpv:
                sc = 0.72
                short = generic[0].label.split("(")[0].strip()
                st = f"Drone FPV ({short} + analógico)"
                ss.extend(non_dji_fpv[:2])
            _update(sc, st, ss)

        # ── Telemetría autónoma (ArduPilot / PX4) ────────────────────────────
        if telem:
            sc, st, ss = 0.50, "Drone autónomo (telemetría detectada)", list(telem[:2])
            non_telem_ctrl = [s for s in ctrl if id(s) not in set(id(x) for x in best_sigs)]
            if non_telem_ctrl:
                sc = 0.80
                st = "Drone autónomo ArduPilot/PX4 (ctrl + telemetría)"
                ss.extend(non_telem_ctrl[:1])
            elif fpv:
                sc = 0.65
                st = "Drone autónomo + FPV"
                ss.extend(fpv[:1])
            _update(sc, st, ss)

        # ── Solo FPV (control fuera de rango) ─────────────────────────────────
        if not ctrl and not telem:
            non_dji_fpv = [s for s in fpv if "DJI" not in s.label]
            if non_dji_fpv:
                sc = 0.38 if len(non_dji_fpv) == 1 else 0.55
                st = "FPV detectado — control fuera de alcance"
                _update(sc, st, non_dji_fpv[:3])

        # ── Bonus por número total de señales ─────────────────────────────────
        total = len(ctrl) + len(fpv) + len(telem)
        if total >= 4:
            best_score = min(best_score + 0.06, 0.98)

        return best_score, best_type, best_sigs

# ──────────────────────────────────────────────────────────────────────────────
#  Acoustic alarm
# ──────────────────────────────────────────────────────────────────────────────

class SoundAlarm:
    """
    Sistema de alarma acústica graduada por nivel de amenaza.

    Genera audio PCM con numpy + stdlib wave, reproduce con aplay (ALSA)
    o paplay (PulseAudio). No requiere dependencias adicionales.

    Patrones:
    - LOW:      un pitido  880 Hz / 0.3 s
    - MEDIUM:   doble pitido
    - HIGH:     cinco pitidos rápidos 1200 Hz
    - CRITICAL: sirena wup-wup (barrido 600→1400 Hz, x2)
    """

    DEFAULT_COOLDOWN = 5.0

    _PATTERNS: dict[str, list[tuple[float, float]]] = {
        "single": [(880.0, 0.30)],
        "double": [(880.0, 0.20), (0.0, 0.10), (880.0, 0.20)],
        "rapid":  [(1200.0, 0.12), (0.0, 0.06)] * 5,
        "siren":  [],   # generado dinámicamente
    }

    def __init__(self) -> None:
        self._enabled  = True
        self._cooldown = self.DEFAULT_COOLDOWN
        self._last_t   = 0.0
        self._lock     = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, v: bool) -> None:
        self._enabled = bool(v)

    @property
    def cooldown(self) -> float:
        return self._cooldown

    @cooldown.setter
    def cooldown(self, v: float) -> None:
        self._cooldown = max(1.0, float(v))

    def play(self, level: ThreatLevel) -> None:
        if not self._enabled or level == ThreatLevel.NONE:
            return
        now = time.monotonic()
        with self._lock:
            if now - self._last_t < self._cooldown:
                return
            self._last_t = now

        key = {
            ThreatLevel.LOW:      "single",
            ThreatLevel.MEDIUM:   "double",
            ThreatLevel.HIGH:     "rapid",
            ThreatLevel.CRITICAL: "siren",
        }.get(level, "single")

        threading.Thread(target=self._play_async, args=(key,), daemon=True).start()

    # ── Audio generation ──────────────────────────────────────────────────────

    def _generate_wav(self, key: str) -> Optional[str]:
        rate = 44100

        if key == "siren":
            # Wup-wup: sweep 600 → 1400 Hz, 0.55 s × 2 repeticiones
            segs = []
            for _ in range(2):
                n    = int(rate * 0.55)
                freq = 600.0 + 800.0 * np.linspace(0.0, 1.0, n, endpoint=False)
                phase = np.cumsum(2.0 * np.pi * freq / rate)
                seg   = np.sin(phase).astype(np.float32) * 0.70
                fade  = int(rate * 0.015)
                seg[:fade]  *= np.linspace(0.0, 1.0, fade)
                seg[-fade:] *= np.linspace(1.0, 0.0, fade)
                segs.append(seg)
                segs.append(np.zeros(int(rate * 0.08), dtype=np.float32))
            samples = np.concatenate(segs)
        else:
            parts  = self._PATTERNS.get(key, self._PATTERNS["single"])
            segs   = []
            for freq, dur in parts:
                n = int(rate * dur)
                if freq == 0.0 or n == 0:
                    segs.append(np.zeros(n, dtype=np.float32))
                else:
                    t   = np.linspace(0.0, dur, n, endpoint=False)
                    seg = np.sin(2.0 * np.pi * freq * t).astype(np.float32) * 0.65
                    fade = min(int(rate * 0.012), n // 4)
                    if fade > 0:
                        seg[:fade]  *= np.linspace(0.0, 1.0, fade)
                        seg[-fade:] *= np.linspace(1.0, 0.0, fade)
                    segs.append(seg)
            samples = np.concatenate(segs)

        pcm  = (samples * 32767.0).clip(-32768, 32767).astype(np.int16)
        tmp  = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        path = tmp.name
        tmp.close()
        with wave.open(path, "w") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(rate)
            wf.writeframes(pcm.tobytes())
        return path

    def _play_async(self, key: str) -> None:
        import sys
        path: Optional[str] = None
        try:
            path = self._generate_wav(key)
            if path is None:
                return
            if sys.platform == "win32":
                try:
                    import winsound
                    winsound.PlaySound(path, winsound.SND_FILENAME)
                    return
                except Exception:
                    pass
            else:
                for cmd in (["aplay", "-q", path], ["paplay", path]):
                    try:
                        r = subprocess.run(cmd, timeout=10.0, capture_output=True)
                        if r.returncode == 0:
                            return
                    except (FileNotFoundError, subprocess.TimeoutExpired):
                        continue
            # Last resort: system bell
            print("\a", end="", flush=True)
        except Exception:
            pass
        finally:
            if path and os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass

# ──────────────────────────────────────────────────────────────────────────────
#  Simulation engine
# ──────────────────────────────────────────────────────────────────────────────

class SimEngine:
    """
    Genera espectros RF simulados físicamente plausibles.

    Modelos de modulación:
    - Wi-Fi:        OFDM — pasabanda plana + caída Gaussiana
    - FPV analógico: FM — portadora + bandas laterales de audio
    - Control drone: FHSS — ráfagas intermitentes (~40 % del tiempo)
    - Telemetría:   LoRa/FSK — pulsos estrechos
    """

    def __init__(self, fft_size: int = 1024) -> None:
        self.fft_size = fft_size
        self._t       = 0.0

    def generate(
        self, center_mhz: float, span_mhz: float
    ) -> tuple[np.ndarray, np.ndarray]:
        self._t += 0.05
        freqs = np.linspace(
            center_mhz - span_mhz / 2,
            center_mhz + span_mhz / 2,
            self.fft_size,
        )
        y = np.abs(np.random.randn(self.fft_size)) * 0.055 + 0.03

        for proto in PROTOCOL_DB:
            dist = np.abs(freqs - proto.freq_mhz)
            if not np.any(dist < proto.bw_mhz * 3.0):
                continue
            p = proto.power
            if proto.category == "wifi":
                flat    = np.where(dist < proto.bw_mhz * 0.38, p, 0.0)
                rolloff = p * np.exp(-(dist ** 2) / (proto.bw_mhz ** 2 * 0.55))
                mod     = np.random.uniform(0.88, 1.0, self.fft_size)
                y      += (flat * 0.6 + rolloff * 0.4) * mod
            elif proto.category == "fpv_video":
                carrier = np.where(dist < 0.25, p, 0.0)
                sb1     = np.where(np.abs(dist - 1.5) < 0.20, p * 0.35, 0.0)
                sb2     = np.where(np.abs(dist - 3.0) < 0.15, p * 0.18, 0.0)
                skirt   = p * 0.25 * np.exp(-(dist ** 2) / (proto.bw_mhz ** 2 * 0.6))
                y      += carrier + sb1 + sb2 + skirt
            elif proto.category in ("drone_ctrl", "telemetry"):
                burst = np.sin(self._t * (5.0 + (proto.freq_mhz % 7)))
                if burst > 0.25:
                    amp = p * (0.70 + 0.30 * burst)
                    y  += amp * np.exp(-(dist ** 2) / (proto.bw_mhz ** 2 * 0.5))

        return freqs, np.clip(y, 0.0, None)

    def resize(self, fft_size: int) -> None:
        self.fft_size = fft_size

# ──────────────────────────────────────────────────────────────────────────────
#  Signal detector
# ──────────────────────────────────────────────────────────────────────────────

def _normalize(spectrum: np.ndarray) -> np.ndarray:
    floor = np.percentile(spectrum, 20)
    peak  = np.percentile(spectrum, 99)
    span  = peak - floor
    if span < 1e-9:
        return np.zeros_like(spectrum, dtype=float)
    return np.clip((spectrum - floor) / span, 0.0, None)


def detect_signals(
    freqs:     np.ndarray,
    spectrum:  np.ndarray,
    threshold: float,
) -> list[DetectedSignal]:
    """
    Detección de señales por pico con coincidencia de protocolo.
    1. Normaliza el espectro usando estimación robusta del noise floor.
    2. Detecta máximos locales por encima del umbral.
    3. Estima el ancho de banda por cruce de semipotencia (−3 dB).
    4. Asocia cada pico a los protocolos conocidos en PROTOCOL_DB.
    """
    norm     = _normalize(spectrum)
    detected: list[DetectedSignal] = []

    for i in range(2, len(norm) - 2):
        if norm[i] < threshold:
            continue
        if not (norm[i] > norm[i-1] >= norm[i-2]
                and norm[i] > norm[i+1] >= norm[i+2]):
            continue

        peak_freq  = float(freqs[i])
        peak_power = float(spectrum[i])

        half  = norm[i] * 0.5
        left  = i
        right = i
        while left  > 0             and norm[left  - 1] >= half:
            left  -= 1
        while right < len(norm) - 1 and norm[right + 1] >= half:
            right += 1
        bw = max(float(freqs[right] - freqs[left]), 0.01)

        label    = f"{peak_freq:.3f} MHz"
        category = "unknown"
        color    = "#6b7280"
        best_d   = float("inf")

        for proto in PROTOCOL_DB:
            dist = abs(proto.freq_mhz - peak_freq)
            if dist < max(proto.bw_mhz, bw) * 1.5 and dist < best_d:
                best_d   = dist
                label    = proto.name
                category = proto.category
                color    = proto.color

        detected.append(DetectedSignal(
            freq_mhz = round(peak_freq, 3),
            power    = round(peak_power, 2),
            bw_mhz   = round(bw, 3),
            label    = label,
            category = category,
            color    = color,
        ))

    return detected

# ──────────────────────────────────────────────────────────────────────────────
#  UI theme
# ──────────────────────────────────────────────────────────────────────────────

STYLESHEET = """
QMainWindow, QWidget {
    background-color: #0d1117;
    color: #c9d1d9;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 11px;
}
QGroupBox {
    border: 1px solid #21262d;
    border-radius: 5px;
    margin-top: 10px;
    padding-top: 10px;
    font-weight: bold;
    color: #58a6ff;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 8px;
    padding: 0 4px;
}
QPushButton {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 5px 12px;
    color: #c9d1d9;
}
QPushButton:hover   { background-color: #1f2937; border-color: #58a6ff; }
QPushButton:pressed { background-color: #0d1117; }
QDoubleSpinBox, QSpinBox, QComboBox {
    background-color: #010409;
    border: 1px solid #30363d;
    border-radius: 3px;
    padding: 3px 6px;
    color: #e6edf3;
    min-height: 22px;
}
QComboBox::drop-down         { border: none; width: 20px; }
QComboBox QAbstractItemView  { background-color: #161b22; border: 1px solid #30363d; }
QSlider::groove:horizontal   { height: 4px; background: #21262d; border-radius: 2px; }
QSlider::handle:horizontal   {
    width: 13px; height: 13px; margin: -5px 0;
    background: #58a6ff; border-radius: 7px;
}
QSlider::sub-page:horizontal { background: #58a6ff; border-radius: 2px; }
QTableWidget {
    background-color: #010409;
    gridline-color: #21262d;
    border: 1px solid #21262d;
    alternate-background-color: #0d1117;
}
QTableWidget::item:selected  { background-color: #1f2937; }
QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    border: none;
    border-right: 1px solid #21262d;
    border-bottom: 1px solid #21262d;
    padding: 4px 8px;
    font-weight: bold;
}
QTextEdit {
    background-color: #010409;
    border: 1px solid #21262d;
    color: #c9d1d9;
    font-family: Consolas, monospace;
    font-size: 10px;
}
QProgressBar {
    border: 1px solid #30363d;
    border-radius: 3px;
    background: #010409;
    color: #ffffff;
    text-align: center;
    font-size: 10px;
}
QProgressBar::chunk { background: #8b949e; border-radius: 2px; }
QStatusBar           { background-color: #161b22; color: #8b949e; border-top: 1px solid #21262d; }
QStatusBar QLabel    { padding: 0 6px; }
QCheckBox            { color: #c9d1d9; spacing: 6px; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid #30363d; border-radius: 3px; background: #010409; }
QCheckBox::indicator:checked { background-color: #1f6feb; border-color: #58a6ff; }
QSplitter::handle    { background: #21262d; }
QScrollBar:vertical  { background: #0d1117; width: 8px; border: none; }
QScrollBar::handle:vertical { background: #30363d; border-radius: 4px; min-height: 20px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""

_BTN_HUNT = (
    "background-color: #238636; color:#ffffff; font-weight:bold;"
    " padding:10px 18px; border:none; border-radius:5px; font-size:13px;"
)
_BTN_STOP = (
    "background-color: #da3633; color:#ffffff; font-weight:bold;"
    " padding:10px 18px; border:none; border-radius:5px; font-size:13px;"
)


def _vsep() -> QFrame:
    s = QFrame()
    s.setFrameShape(QFrame.VLine)
    s.setStyleSheet("color: #21262d;")
    return s

# ──────────────────────────────────────────────────────────────────────────────
#  Main window
# ──────────────────────────────────────────────────────────────────────────────

class DroneHunterWindow(QMainWindow):
    """
    DroneHunter — Ventana principal.

    Copyright (c) 2026 E.B.G  |  Uso Personal — No Comercial
    """

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(
            f"DroneHunter  v{__version__}  ·  © {__year__} {__author__}"
            "  ·  Sistema de Detección RF"
        )
        self.resize(1480, 900)
        self.setMinimumSize(960, 640)

        # State
        self.is_running     = False
        self.mode           = "sim"
        self.center_mhz     = 2440.0
        self.span_mhz       = 40.0
        self.fft_size       = 1024
        self.waterfall_rows = 200
        self.threshold      = 0.35
        self.sdr            = None
        self._wf            = np.zeros((self.waterfall_rows, self.fft_size))
        self._peak_hold: Optional[np.ndarray] = None
        self._last_level    = ThreatLevel.NONE
        self._fps_n         = 0
        self._fps_ts        = time.monotonic()
        self._all_detections: list[DetectedSignal] = []

        # Core engines
        self._sim       = SimEngine(self.fft_size)
        self._classifier = DroneClassifier(persistence=6)
        self._alarm      = SoundAlarm()

        # UI
        self.setStyleSheet(STYLESHEET)
        pg.setConfigOption("background", "#0d1117")
        pg.setConfigOption("foreground", "#8b949e")
        self._build_ui()
        self._build_statusbar()

        # Timer ~30 FPS
        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self._tick)

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        vroot = QVBoxLayout(root)
        vroot.setContentsMargins(0, 0, 0, 0)
        vroot.setSpacing(0)

        # ── Full-width threat banner ──────────────────────────────────────────
        self.threat_banner = QLabel()
        self.threat_banner.setAlignment(Qt.AlignCenter)
        self.threat_banner.setFixedHeight(62)
        self.threat_banner.setStyleSheet(
            "background:#0d1117; color:#8b949e;"
            " border-bottom:2px solid #21262d;"
            " font-size:15px; font-weight:bold;"
        )
        self.threat_banner.setText("  SIN AMENAZA  —  Esperando inicio…")
        vroot.addWidget(self.threat_banner)

        # ── Main content row ──────────────────────────────────────────────────
        content = QWidget()
        hlay    = QHBoxLayout(content)
        hlay.setContentsMargins(6, 6, 6, 6)
        hlay.setSpacing(6)

        hlay.addWidget(self._build_control_panel())

        center = QSplitter(Qt.Vertical)
        center.addWidget(self._build_plots())
        center.addWidget(self._build_detections_table())
        center.setSizes([600, 180])
        hlay.addWidget(center, stretch=1)

        hlay.addWidget(self._build_threat_panel())
        vroot.addWidget(content, stretch=1)

    # ── Left control panel ────────────────────────────────────────────────────

    def _build_control_panel(self) -> QWidget:
        panel = QWidget()
        panel.setFixedWidth(240)
        lay   = QVBoxLayout(panel)
        lay.setSpacing(8)

        # Start/Stop
        self.btn_toggle = QPushButton("▶  INICIAR CAZA")
        self.btn_toggle.setStyleSheet(_BTN_HUNT)
        self.btn_toggle.setMinimumHeight(42)
        self.btn_toggle.clicked.connect(self._toggle)
        lay.addWidget(self.btn_toggle)

        # Mode
        mode_box = QGroupBox("Modo de operación")
        m_lay    = QVBoxLayout(mode_box)
        self.combo_mode = QComboBox()
        self.combo_mode.addItems(["Simulación", "HackRF One (USB)"])
        self.combo_mode.currentIndexChanged.connect(self._on_mode_change)
        m_lay.addWidget(self.combo_mode)
        lay.addWidget(mode_box)

        # Frequency
        freq_box = QGroupBox("Sintonización")
        f_lay    = QFormLayout(freq_box)
        self.spin_center = QDoubleSpinBox()
        self.spin_center.setRange(1.0, 6000.0)
        self.spin_center.setValue(self.center_mhz)
        self.spin_center.setSuffix(" MHz")
        self.spin_center.setDecimals(3)
        self.spin_center.setStepType(QDoubleSpinBox.AdaptiveDecimalStepType)
        self.spin_center.valueChanged.connect(self._on_freq_change)
        f_lay.addRow("Centro:", self.spin_center)
        self.combo_span = QComboBox()
        self.combo_span.addItems([f"{v:g} MHz" for v in SPAN_OPTIONS_MHZ])
        self.combo_span.setCurrentIndex(5)  # 40 MHz
        self.combo_span.currentIndexChanged.connect(
            lambda i: self._on_span_change(SPAN_OPTIONS_MHZ[i])
        )
        f_lay.addRow("Span:", self.combo_span)
        lay.addWidget(freq_box)

        # Band presets
        band_box = QGroupBox("Bandas predefinidas")
        b_lay    = QVBoxLayout(band_box)
        for label, freq in BAND_PRESETS:
            btn = QPushButton(label)
            btn.clicked.connect(lambda _, f=freq: self.spin_center.setValue(f))
            b_lay.addWidget(btn)
        lay.addWidget(band_box)

        # HackRF gain (hidden in sim mode)
        self.gain_box = QGroupBox("Ganancia HackRF")
        g_lay = QFormLayout(self.gain_box)
        self.slider_lna = QSlider(Qt.Horizontal)
        self.slider_lna.setRange(0, 5)
        self.slider_lna.setValue(3)
        self.lbl_lna = QLabel("24 dB")
        self.slider_lna.valueChanged.connect(
            lambda v: (self.lbl_lna.setText(f"{v*8} dB"), self._apply_gain())
        )
        g_lay.addRow("LNA:", self.slider_lna)
        g_lay.addRow("",    self.lbl_lna)
        self.slider_vga = QSlider(Qt.Horizontal)
        self.slider_vga.setRange(0, 31)
        self.slider_vga.setValue(20)
        self.lbl_vga = QLabel("40 dB")
        self.slider_vga.valueChanged.connect(
            lambda v: (self.lbl_vga.setText(f"{v*2} dB"), self._apply_gain())
        )
        g_lay.addRow("VGA:", self.slider_vga)
        g_lay.addRow("",    self.lbl_vga)
        self.check_amp = QCheckBox("Amplificador RF (+14 dB)")
        self.check_amp.stateChanged.connect(lambda _: self._apply_gain())
        g_lay.addRow(self.check_amp)
        lay.addWidget(self.gain_box)
        self.gain_box.hide()

        # Detection settings
        det_box = QGroupBox("Detección")
        d_lay   = QFormLayout(det_box)
        self.slider_thresh = QSlider(Qt.Horizontal)
        self.slider_thresh.setRange(5, 90)
        self.slider_thresh.setValue(35)
        self.lbl_thresh = QLabel("0.35")
        self.slider_thresh.valueChanged.connect(
            lambda v: (
                setattr(self, "threshold", v / 100.0),
                self.lbl_thresh.setText(f"{v/100:.2f}"),
            )
        )
        d_lay.addRow("Umbral:", self.slider_thresh)
        d_lay.addRow("",        self.lbl_thresh)

        self.spin_persist = QSpinBox()
        self.spin_persist.setRange(1, 30)
        self.spin_persist.setValue(6)
        self.spin_persist.setSuffix(" frames")
        self.spin_persist.valueChanged.connect(
            lambda v: setattr(self._classifier, "persistence", v)
        )
        d_lay.addRow("Persistencia:", self.spin_persist)
        lay.addWidget(det_box)

        # Alarm settings
        alarm_box = QGroupBox("Alarma acústica")
        a_lay     = QFormLayout(alarm_box)
        self.check_alarm = QCheckBox("Activar alarma")
        self.check_alarm.setChecked(True)
        self.check_alarm.stateChanged.connect(
            lambda s: setattr(self._alarm, "enabled", bool(s))
        )
        a_lay.addRow(self.check_alarm)
        self.slider_cooldown = QSlider(Qt.Horizontal)
        self.slider_cooldown.setRange(1, 30)
        self.slider_cooldown.setValue(5)
        self.lbl_cooldown = QLabel("5 s")
        self.slider_cooldown.valueChanged.connect(
            lambda v: (
                setattr(self._alarm, "cooldown", float(v)),
                self.lbl_cooldown.setText(f"{v} s"),
            )
        )
        a_lay.addRow("Cooldown:", self.slider_cooldown)
        a_lay.addRow("",          self.lbl_cooldown)
        btn_test = QPushButton("🔊  Probar alarma")
        btn_test.clicked.connect(lambda: self._alarm.play(ThreatLevel.HIGH))
        a_lay.addRow(btn_test)
        lay.addWidget(alarm_box)

        # Export
        exp_box = QGroupBox("Exportar")
        e_lay   = QVBoxLayout(exp_box)
        btn_csv = QPushButton("💾  Guardar detecciones (CSV)")
        btn_csv.clicked.connect(self._export_csv)
        e_lay.addWidget(btn_csv)
        btn_rst = QPushButton("⟳  Resetear clasificador")
        btn_rst.clicked.connect(self._reset)
        e_lay.addWidget(btn_rst)
        lay.addWidget(exp_box)

        lay.addStretch()

        footer = QLabel(
            f"© {__year__} <b>{__author__}</b>  ·  Uso Personal\n"
            f"DroneHunter  v{__version__}"
        )
        footer.setAlignment(Qt.AlignCenter)
        footer.setStyleSheet("color:#484f58; font-size:9px; padding:4px;")
        lay.addWidget(footer)

        return panel

    # ── Spectrum + waterfall plots ────────────────────────────────────────────

    def _build_plots(self) -> QWidget:
        widget = QWidget()
        lay    = QVBoxLayout(widget)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)

        # Spectrum
        self.plot_spectrum = pg.PlotWidget()
        self.plot_spectrum.setTitle(
            "<span style='color:#58a6ff;font-size:12px;font-weight:bold'>"
            "Analizador de Espectro RF</span>"
        )
        self.plot_spectrum.showGrid(x=True, y=True, alpha=0.12)
        self.plot_spectrum.setLabel("bottom", "Frecuencia", units="MHz")
        self.plot_spectrum.setLabel("left",   "Nivel")
        self.plot_spectrum.setMinimumHeight(200)

        self.curve_spectrum = self.plot_spectrum.plot(
            pen=pg.mkPen("#10b981", width=1.5),
            fillLevel=0,
            brush=(16, 185, 129, 20),
        )
        self.curve_peak = self.plot_spectrum.plot(
            pen=pg.mkPen(color="#f59e0b", width=1, style=Qt.DashLine),
        )
        self.cf_line = pg.InfiniteLine(
            angle=90, movable=True,
            pen=pg.mkPen("#58a6ff", width=1, style=Qt.DotLine),
            label="CF",
            labelOpts={"color": "#58a6ff", "position": 0.95},
        )
        self.cf_line.setPos(self.center_mhz)
        self.cf_line.sigPositionChangeFinished.connect(
            lambda ln: self.spin_center.setValue(ln.value())
        )
        self.plot_spectrum.addItem(self.cf_line)
        lay.addWidget(self.plot_spectrum, stretch=3)

        # Waterfall
        gw = pg.GraphicsLayoutWidget()
        self.plot_wf = gw.addPlot()
        self.plot_wf.setTitle(
            "<span style='color:#58a6ff;font-size:12px;font-weight:bold'>"
            "Cascada (Waterfall)</span>"
        )
        self.plot_wf.setLabel("bottom", "Frecuencia", units="MHz")
        self.plot_wf.setLabel("left",   "Tiempo ↓")

        self.wf_img = pg.ImageItem()
        self.plot_wf.addItem(self.wf_img)

        cmap = pg.ColorMap(
            pos=np.array([0.00, 0.18, 0.40, 0.65, 0.85, 1.00]),
            color=np.array([
                [ 10,  10,  30, 255],
                [ 20,  40, 140, 255],
                [ 16, 185, 129, 255],
                [234, 179,   8, 255],
                [239,  68,  68, 255],
                [255, 255, 255, 255],
            ], dtype=np.ubyte),
        )
        self.wf_img.setColorMap(cmap)
        gw.setMinimumHeight(200)
        lay.addWidget(gw, stretch=3)
        return widget

    # ── Detections table (bottom) ─────────────────────────────────────────────

    def _build_detections_table(self) -> QWidget:
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)

        lbl = QLabel("  SEÑALES DETECTADAS EN TIEMPO REAL")
        lbl.setStyleSheet(
            "color:#58a6ff; font-weight:bold; font-size:11px; padding:4px 0;"
        )
        lay.addWidget(lbl)

        self.table_signals = QTableWidget(0, 5)
        self.table_signals.setHorizontalHeaderLabels(
            ["Hora", "Frecuencia (MHz)", "Nivel", "BW (MHz)", "Protocolo / Categoría"]
        )
        self.table_signals.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_signals.setAlternatingRowColors(True)
        self.table_signals.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table_signals.setSelectionBehavior(QTableWidget.SelectRows)
        lay.addWidget(self.table_signals)
        return w

    # ── Right threat panel ────────────────────────────────────────────────────

    def _build_threat_panel(self) -> QWidget:
        panel = QWidget()
        panel.setFixedWidth(275)
        lay   = QVBoxLayout(panel)
        lay.setContentsMargins(0, 0, 4, 0)
        lay.setSpacing(6)

        # Header
        hdr = QLabel("  ANÁLISIS DE AMENAZA")
        hdr.setStyleSheet(
            "color:#58a6ff; font-weight:bold; font-size:11px;"
            " padding:4px 0; border-bottom:1px solid #21262d;"
        )
        lay.addWidget(hdr)

        # Confidence bar
        lay.addWidget(self._small_label("  Confianza de detección:"))

        self.confidence_bar = QProgressBar()
        self.confidence_bar.setRange(0, 100)
        self.confidence_bar.setValue(0)
        self.confidence_bar.setFormat("%v %")
        self.confidence_bar.setFixedHeight(24)
        lay.addWidget(self.confidence_bar)

        # Drone type
        self.lbl_dtype = QLabel("—")
        self.lbl_dtype.setWordWrap(True)
        self.lbl_dtype.setStyleSheet(
            "color:#c9d1d9; font-size:12px; font-weight:bold; padding:6px 4px;"
        )
        lay.addWidget(self.lbl_dtype)

        # Matching signals
        lay.addWidget(self._small_label("  Señales coincidentes:"))
        self.table_match = QTableWidget(0, 3)
        self.table_match.setHorizontalHeaderLabels(["Protocolo", "MHz", "Tipo"])
        self.table_match.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_match.verticalHeader().hide()
        self.table_match.setMaximumHeight(160)
        self.table_match.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.table_match)

        # Alert log
        lay.addWidget(self._small_label("  Registro de alertas:"))
        self.alert_log = QTextEdit()
        self.alert_log.setReadOnly(True)
        lay.addWidget(self.alert_log, stretch=1)

        # Clear log + export buttons
        btn_row = QWidget()
        br_lay  = QHBoxLayout(btn_row)
        br_lay.setContentsMargins(0, 0, 0, 0)
        btn_clr_log = QPushButton("🗑  Limpiar log")
        btn_clr_log.clicked.connect(self.alert_log.clear)
        br_lay.addWidget(btn_clr_log)
        lay.addWidget(btn_row)

        return panel

    def _small_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(
            "color:#8b949e; font-size:10px;"
            " border-top:1px solid #21262d; padding-top:4px; margin-top:2px;"
        )
        return lbl

    # ── Status bar ────────────────────────────────────────────────────────────

    def _build_statusbar(self) -> None:
        sb = self.statusBar()
        self.lbl_mode   = QLabel("⬤  Simulación")
        self.lbl_mode.setStyleSheet("color:#3fb950;")
        self.lbl_cf     = QLabel(f"CF: {self.center_mhz:.3f} MHz")
        self.lbl_span_s = QLabel(f"Span: 40 MHz")
        self.lbl_threat = QLabel("Amenaza: NINGUNA")
        self.lbl_conf   = QLabel("Confianza: 0 %")
        self.lbl_sigs   = QLabel("Señales: 0")
        self.lbl_fps    = QLabel("FPS: —")
        for w in (self.lbl_mode, _vsep(), self.lbl_cf, _vsep(), self.lbl_span_s,
                  _vsep(), self.lbl_threat, _vsep(), self.lbl_conf, _vsep(), self.lbl_sigs):
            sb.addWidget(w)
        sb.addPermanentWidget(self.lbl_fps)

    # ── Control logic ─────────────────────────────────────────────────────────

    def _toggle(self) -> None:
        if self.is_running:
            self._stop()
        else:
            self._start()

    def _start(self) -> None:
        if self.mode == "real" and not self._connect_hackrf():
            return
        self.is_running  = True
        self._peak_hold  = None
        self.btn_toggle.setText("■  DETENER CAZA")
        self.btn_toggle.setStyleSheet(_BTN_STOP)
        self._timer.start()

    def _stop(self) -> None:
        self.is_running = False
        self._timer.stop()
        self.btn_toggle.setText("▶  INICIAR CAZA")
        self.btn_toggle.setStyleSheet(_BTN_HUNT)
        if self.sdr is not None:
            try:
                self.sdr.close()
            except Exception:
                pass
            self.sdr = None

    def _on_mode_change(self, idx: int) -> None:
        self.mode = "real" if idx == 1 else "sim"
        if self.mode == "real":
            self.gain_box.show()
            self.lbl_mode.setText("⬤  HackRF One")
            self.lbl_mode.setStyleSheet("color:#f59e0b;")
        else:
            self.gain_box.hide()
            self.lbl_mode.setText("⬤  Simulación")
            self.lbl_mode.setStyleSheet("color:#3fb950;")

    def _on_freq_change(self, val: float) -> None:
        self.center_mhz = val
        self.cf_line.setPos(val)
        self.lbl_cf.setText(f"CF: {val:.3f} MHz")
        if self.mode == "real" and self.sdr is not None:
            try:
                self.sdr.center_freq = int(val * 1e6)
            except Exception:
                pass

    def _on_span_change(self, val: float) -> None:
        self.span_mhz = val
        self.lbl_span_s.setText(f"Span: {val:g} MHz")

    def _apply_gain(self) -> None:
        if self.mode == "real" and self.sdr is not None:
            try:
                self.sdr.lna_gain     = self.slider_lna.value() * 8
                self.sdr.vga_gain     = self.slider_vga.value() * 2
                self.sdr.amplifier_on = self.check_amp.isChecked()
            except Exception:
                pass

    def _connect_hackrf(self) -> bool:
        if not HACKRF_AVAILABLE:
            QMessageBox.warning(
                self, "Librería no encontrada",
                "La librería 'hackrf' no está instalada.\n\n"
                "Instálala con:\n    pip install HackRF\n\n"
                "Usando modo Simulación.",
            )
            self.combo_mode.setCurrentIndex(0)
            return False
        try:
            self.sdr              = HackRF()
            self.sdr.sample_rate  = 20e6
            self.sdr.center_freq  = int(self.center_mhz * 1e6)
            self.sdr.lna_gain     = self.slider_lna.value() * 8
            self.sdr.vga_gain     = self.slider_vga.value() * 2
            self.sdr.amplifier_on = self.check_amp.isChecked()
            return True
        except Exception as exc:
            QMessageBox.critical(
                self, "Error de hardware",
                f"No se pudo conectar al HackRF.\n"
                f"Comprueba que esté conectado por USB.\n\nDetalle: {exc}",
            )
            self.combo_mode.setCurrentIndex(0)
            return False

    def _reset(self) -> None:
        self._classifier.reset()
        self._peak_hold = None
        self._all_detections.clear()
        self.table_signals.setRowCount(0)
        self.table_match.setRowCount(0)
        self._update_threat_display(
            ThreatReport(ThreatLevel.NONE, 0.0, "—", [])
        )

    # ── Main update tick ──────────────────────────────────────────────────────

    def _tick(self) -> None:
        # 1. Acquire spectrum
        if self.mode == "sim":
            freqs, spectrum = self._sim.generate(self.center_mhz, self.span_mhz)
        else:
            if self.sdr is None:
                return
            try:
                n       = self.fft_size
                samples = self.sdr.read_samples(n)
                window  = np.blackman(n)
                fft_out = np.fft.fftshift(np.fft.fft(samples[:n] * window, n))
                spectrum = 10.0 * np.log10(np.abs(fft_out) ** 2 + 1e-12)
                freqs = np.linspace(
                    self.center_mhz - self.span_mhz / 2,
                    self.center_mhz + self.span_mhz / 2,
                    n,
                )
            except Exception as exc:
                self.statusBar().showMessage(f"HackRF error: {exc}", 2000)
                return

        # 2. Resize waterfall if needed
        if len(spectrum) != self._wf.shape[1]:
            self._wf        = np.zeros((self.waterfall_rows, len(spectrum)))
            self._peak_hold = None

        # 3. Peak hold (slow exponential decay)
        if self._peak_hold is None or len(self._peak_hold) != len(spectrum):
            self._peak_hold = spectrum.copy()
        else:
            np.maximum(self._peak_hold, spectrum, out=self._peak_hold)
            self._peak_hold *= 0.9985

        # 4. Spectrum plot
        self.curve_spectrum.setData(freqs, spectrum)
        self.curve_peak.setData(freqs, self._peak_hold)
        self.plot_spectrum.setXRange(freqs[0], freqs[-1], padding=0)

        # 5. Waterfall
        self._wf    = np.roll(self._wf, 1, axis=0)
        self._wf[0] = spectrum
        levels = (0.0, 1.2) if self.mode == "sim" else (-110.0, -20.0)
        self.wf_img.setImage(self._wf.T, autoLevels=False, levels=levels)
        rect = pg.QtCore.QRectF(freqs[0], 0, freqs[-1] - freqs[0], self.waterfall_rows)
        self.wf_img.setRect(rect)
        self.plot_wf.setXRange(freqs[0], freqs[-1], padding=0)

        # 6. Detect signals
        new_sigs = detect_signals(freqs, spectrum, self.threshold)
        if new_sigs:
            self._add_signals_to_table(new_sigs)
        self.lbl_sigs.setText(f"Señales: {len(new_sigs)}")

        # 7. Classify → threat
        report = self._classifier.update(new_sigs)
        self._update_threat_display(report)

        # 8. Sound alarm
        if report.level != ThreatLevel.NONE:
            self._alarm.play(report.level)

        # 9. FPS
        self._fps_n += 1
        elapsed = time.monotonic() - self._fps_ts
        if elapsed >= 1.0:
            self.lbl_fps.setText(f"FPS: {self._fps_n / elapsed:.1f}")
            self._fps_n  = 0
            self._fps_ts = time.monotonic()

    # ── Threat display update ─────────────────────────────────────────────────

    def _update_threat_display(self, report: ThreatReport) -> None:
        cfg  = THREAT_CFG[report.level]
        pct  = int(report.confidence * 100)

        # Banner
        self.threat_banner.setText(
            f"  {cfg['label']}   —   {pct} %   —   {report.drone_type}"
        )
        self.threat_banner.setStyleSheet(
            f"background:{cfg['bg']}; color:{cfg['fg']};"
            f" border-bottom:2px solid {cfg['border']};"
            f" font-size:15px; font-weight:bold;"
        )

        # Confidence bar
        self.confidence_bar.setValue(pct)
        self.confidence_bar.setStyleSheet(
            f"QProgressBar {{ border:1px solid #30363d; border-radius:3px;"
            f" background:#010409; color:#ffffff; text-align:center; font-size:11px; }}"
            f"QProgressBar::chunk {{ background:{cfg['fg']}; border-radius:2px; }}"
        )

        # Drone type label
        self.lbl_dtype.setText(report.drone_type)
        self.lbl_dtype.setStyleSheet(
            f"color:{cfg['fg']}; font-size:12px; font-weight:bold; padding:6px 4px;"
        )

        # Matching signals table
        self.table_match.setRowCount(0)
        for sig in report.signals:
            r = self.table_match.rowCount()
            self.table_match.insertRow(r)
            items = [
                sig.label.split("(")[0].strip(),
                f"{sig.freq_mhz:.1f}",
                sig.category,
            ]
            col_color = QColor(sig.color)
            for c, val in enumerate(items):
                item = QTableWidgetItem(val)
                item.setForeground(col_color)
                self.table_match.setItem(r, c, item)

        # Status bar
        self.lbl_threat.setText(f"Amenaza: {cfg['label'].replace('⚠','').replace('🔴','').replace('🚨','').strip()}")
        self.lbl_threat.setStyleSheet(f"color:{cfg['fg']};")
        self.lbl_conf.setText(f"Confianza: {pct} %")

        # Alert log — only on level escalation or new type
        if (report.level != ThreatLevel.NONE
                and (report.level != self._last_level
                     or (report.level.value >= ThreatLevel.HIGH.value))):
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            sigs_str = ", ".join(s.label.split("(")[0].strip() for s in report.signals[:3])
            self.alert_log.append(
                f'<span style="color:{cfg["fg"]}">'
                f'[{ts}] <b>{cfg["label"]}</b>  {pct}%  —  {report.drone_type}'
                f'{"<br>&nbsp;&nbsp;&nbsp;Señales: " + sigs_str if sigs_str else ""}'
                f"</span>"
            )
            self.alert_log.verticalScrollBar().setValue(
                self.alert_log.verticalScrollBar().maximum()
            )

        self._last_level = report.level

    # ── Helpers ───────────────────────────────────────────────────────────────

    _MAX_TABLE = 500

    def _add_signals_to_table(self, signals: list[DetectedSignal]) -> None:
        cat_labels = {
            "drone_ctrl": "Ctrl Drone",
            "fpv_video":  "FPV Vídeo",
            "telemetry":  "Telemetría",
            "wifi":       "Wi-Fi",
            "unknown":    "Desconocido",
        }
        for sig in signals[:12]:
            if self.table_signals.rowCount() >= self._MAX_TABLE:
                self.table_signals.removeRow(0)
            r = self.table_signals.rowCount()
            self.table_signals.insertRow(r)
            vals  = [
                sig.timestamp,
                f"{sig.freq_mhz:.3f}",
                f"{sig.power:.2f}",
                f"{sig.bw_mhz:.3f}",
                f"{sig.label}  [{cat_labels.get(sig.category, sig.category)}]",
            ]
            color = QColor(sig.color)
            for c, val in enumerate(vals):
                item = QTableWidgetItem(val)
                item.setForeground(color)
                self.table_signals.setItem(r, c, item)
        self.table_signals.scrollToBottom()

    def _export_csv(self) -> None:
        default = f"dronehunter_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self, "Guardar detecciones", default, "CSV (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow([
                    self.table_signals.horizontalHeaderItem(c).text()
                    for c in range(self.table_signals.columnCount())
                ])
                for row in range(self.table_signals.rowCount()):
                    writer.writerow([
                        (self.table_signals.item(row, col) or QTableWidgetItem("")).text()
                        for col in range(self.table_signals.columnCount())
                    ])
            self.statusBar().showMessage(f"Exportado → {path}", 4000)
        except OSError as exc:
            QMessageBox.critical(self, "Error al exportar", str(exc))

    def closeEvent(self, event) -> None:   # type: ignore[override]
        self._stop()
        super().closeEvent(event)

# ──────────────────────────────────────────────────────────────────────────────
#  License agreement dialog
# ──────────────────────────────────────────────────────────────────────────────

LICENSE_TEXT = """\
DroneHunter  v{version}  ·  Sistema de Detección RF
Copyright (c) {year} E.B.G — All Rights Reserved

══════════════════════════════════════════════════════════════
LICENCIA DE USO / TERMS OF USE
══════════════════════════════════════════════════════════════

✔  PERMITIDO:
   • Uso estrictamente personal, educativo o de investigación.
   • Sin fines comerciales, lucrativos ni institucionales.
   • Distribución del código original íntegro con esta licencia intacta.

✘  PROHIBIDO sin autorización expresa y por escrito del autor:
   • Uso comercial o empresarial de cualquier tipo.
   • Uso gubernamental, institucional o de administración pública.
   • Uso militar, policial, de inteligencia o defensa.
   • Integración en productos o servicios comerciales.
   • Redistribución con modificaciones sin permiso escrito.
   • Descompilación, desempaquetado, ingeniería inversa o cualquier
     otro método destinado a extraer, reproducir o modificar el
     código fuente, total o parcialmente.

══════════════════════════════════════════════════════════════
AVISO LEGAL
══════════════════════════════════════════════════════════════

Este software se proporciona «tal cual», sin garantía de ningún tipo.
El autor no se hace responsable del uso indebido, ilegal o no autorizado
de esta herramienta. El usuario es el único responsable del cumplimiento
de las leyes y regulaciones aplicables en su jurisdicción (incluyendo
normativa de radiofrecuencia, privacidad y seguridad nacional).

El uso de esta aplicación con hardware de RF real puede estar regulado
por la legislación de tu país. Asegúrate de contar con los permisos
necesarios antes de operar.

══════════════════════════════════════════════════════════════
CONTACTO / SOLICITUD DE PERMISOS
══════════════════════════════════════════════════════════════

   E.B.G  ►  hacklabosofficial@proton.me

Al hacer clic en «ACEPTO» confirmas que has leído, comprendido y
aceptado íntegramente estos términos y condiciones de uso.
"""


class LicenseDialog(QWidget):
    """
    Pantalla de aceptación de licencia que se muestra en cada inicio.
    El programa no arranca hasta que el usuario hace clic en ACEPTO.
    """

    def __init__(self) -> None:
        super().__init__()
        self.accepted = False
        self.setWindowTitle(
            f"DroneHunter v{__version__}  ·  Términos y Condiciones de Uso"
        )
        self.setFixedSize(720, 560)
        self.setStyleSheet(
            "QWidget { background:#0d1117; color:#c9d1d9;"
            " font-family:Consolas,'Courier New',monospace; font-size:11px; }"
            "QTextEdit { background:#010409; border:1px solid #21262d;"
            " color:#c9d1d9; font-size:11px; }"
            "QPushButton { padding:8px 28px; border-radius:5px;"
            " font-weight:bold; font-size:12px; border:none; }"
            "QCheckBox { font-size:11px; color:#c9d1d9; spacing:8px; }"
            "QCheckBox::indicator { width:16px; height:16px;"
            " border:1px solid #30363d; border-radius:3px; background:#010409; }"
            "QCheckBox::indicator:checked { background:#1f6feb; border-color:#58a6ff; }"
        )
        self._build()

    def _build(self) -> None:
        from PyQt5.QtGui import QFont
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(12)

        # ── Logo / title ────────────────────────────────────────────────────
        title = QLabel("DRONEHUNTER")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            "color:#58a6ff; font-size:26px; font-weight:bold;"
            " letter-spacing:4px;"
        )
        lay.addWidget(title)

        sub = QLabel(f"v{__version__}  ·  Sistema de Detección RF  ·  © {__year__} {__author__}")
        sub.setAlignment(Qt.AlignCenter)
        sub.setStyleSheet("color:#8b949e; font-size:10px; margin-bottom:4px;")
        lay.addWidget(sub)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("color:#21262d;")
        lay.addWidget(sep)

        # ── License text ───────────────────────────────────────────────────
        self._txt = QTextEdit()
        self._txt.setReadOnly(True)
        self._txt.setPlainText(
            LICENSE_TEXT.format(version=__version__, year=__year__)
        )
        self._txt.setFont(QFont("Consolas", 10))
        lay.addWidget(self._txt, stretch=1)

        # ── Scroll-to-bottom hint ─────────────────────────────────────────
        self._hint = QLabel(
            "▼  Desplázate hacia abajo para leer los términos completos"
        )
        self._hint.setAlignment(Qt.AlignCenter)
        self._hint.setStyleSheet("color:#484f58; font-size:10px;")
        lay.addWidget(self._hint)
        self._txt.verticalScrollBar().valueChanged.connect(self._on_scroll)

        # ── Checkbox ──────────────────────────────────────────────────────
        self._check = QCheckBox(
            "He leído, comprendo y acepto íntegramente los términos y condiciones de uso."
        )
        self._check.stateChanged.connect(self._on_check)
        lay.addWidget(self._check)

        # ── Buttons ──────────────────────────────────────────────────────────
        btn_row = QWidget()
        br_lay  = QHBoxLayout(btn_row)
        br_lay.setContentsMargins(0, 0, 0, 0)
        br_lay.addStretch()

        self._btn_decline = QPushButton("NO ACEPTO  —  Salir")
        self._btn_decline.setStyleSheet(
            "background:#21262d; color:#8b949e;"
        )
        self._btn_decline.clicked.connect(self._decline)
        br_lay.addWidget(self._btn_decline)

        br_lay.addSpacing(12)

        self._btn_accept = QPushButton("✔  ACEPTO — Iniciar programa")
        self._btn_accept.setEnabled(False)
        self._btn_accept.setStyleSheet(
            "background:#21262d; color:#484f58;"
        )
        self._btn_accept.clicked.connect(self._accept)
        br_lay.addWidget(self._btn_accept)

        lay.addWidget(btn_row)

    def _on_scroll(self, val: int) -> None:
        sb  = self._txt.verticalScrollBar()
        pct = val / max(sb.maximum(), 1)
        if pct >= 0.90:
            self._hint.hide()

    def _on_check(self, state: int) -> None:
        ok = bool(state)
        self._btn_accept.setEnabled(ok)
        self._btn_accept.setStyleSheet(
            "background:#238636; color:#ffffff;"
            if ok else
            "background:#21262d; color:#484f58;"
        )

    def _accept(self) -> None:
        self.accepted = True
        self.close()

    def _decline(self) -> None:
        self.accepted = False
        self.close()


# ──────────────────────────────────────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
#  Trial / License system
# ──────────────────────────────────────────────────────────────────────────────

_TRIAL_DAYS   = 3
_LIC_DIR      = os.path.join(os.path.expanduser("~"), ".config", "drone_hunter")
_LIC_STATE    = os.path.join(_LIC_DIR, ".state")
_LIC_KEY_FILE = os.path.join(_LIC_DIR, "license.key")
# Internal secret — never expose this value
_SECRET       = b"dh\x1f\x9aEBG\x00\x2026\x7fk3\xc5"


def _hmac(data: str) -> str:
    return hmac.new(_SECRET, data.encode(), hashlib.sha256).hexdigest()


def _read_trial_start() -> float | None:
    """Return the first-run timestamp if the state file is intact, else None."""
    try:
        with open(_LIC_STATE) as f:
            obj = json.load(f)
        ts_str = str(obj["ts"])
        if hmac.compare_digest(obj["sig"], _hmac(ts_str)):
            return float(ts_str)
    except Exception:
        pass
    return None


def _write_trial_start() -> float:
    os.makedirs(_LIC_DIR, exist_ok=True)
    ts = time.time()
    ts_str = str(ts)
    with open(_LIC_STATE, "w") as f:
        json.dump({"ts": ts_str, "sig": _hmac(ts_str)}, f)
    return ts


def _check_license_key() -> bool:
    """Accept a license.key file containing a valid activation code."""
    try:
        key = open(_LIC_KEY_FILE).read().strip()
        # Valid key = HMAC-SHA256("LICENSED:" + key[:16], SECRET)[:32]
        prefix = key[:16]
        expected = _hmac(f"LICENSED:{prefix}")[:32]
        return hmac.compare_digest(key[16:48], expected)
    except Exception:
        return False


def _trial_status() -> tuple[bool, int]:
    """Returns (is_valid, days_remaining). days_remaining < 0 means expired."""
    if _check_license_key():
        return True, 9999

    ts = _read_trial_start()
    if ts is None:
        ts = _write_trial_start()

    elapsed = (time.time() - ts) / 86400
    remaining = int(_TRIAL_DAYS - elapsed)
    return elapsed <= _TRIAL_DAYS, remaining


class TrialExpiredDialog(QWidget):
    """Shown when the 3-day trial period has ended."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("DroneHunter — Período de prueba finalizado")
        self.setFixedSize(560, 340)
        self.setStyleSheet(
            "QWidget{background:#0d1117;color:#c9d1d9;"
            "font-family:Consolas,'Courier New',monospace;font-size:11px;}"
            "QPushButton{padding:8px 24px;border-radius:5px;font-weight:bold;"
            "font-size:12px;border:none;}"
        )
        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(14)

        icon_lbl = QLabel("⏱")
        icon_lbl.setAlignment(Qt.AlignCenter)
        icon_lbl.setStyleSheet("font-size:48px;")
        lay.addWidget(icon_lbl)

        title = QLabel("PERÍODO DE PRUEBA FINALIZADO")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            "color:#f85149;font-size:17px;font-weight:bold;letter-spacing:2px;"
        )
        lay.addWidget(title)

        msg = QLabel(
            "Tu período de prueba gratuito de 3 días ha expirado.\n\n"
            "Para continuar usando DroneHunter, solicita una licencia\n"
            "de uso personal al autor:"
        )
        msg.setAlignment(Qt.AlignCenter)
        msg.setStyleSheet("color:#8b949e;font-size:11px;line-height:1.6;")
        msg.setWordWrap(True)
        lay.addWidget(msg)

        email = QLabel("hacklabosofficial@proton.me")
        email.setAlignment(Qt.AlignCenter)
        email.setStyleSheet(
            "color:#58a6ff;font-size:13px;font-weight:bold;"
            "background:#161b22;border:1px solid #30363d;"
            "border-radius:6px;padding:8px 16px;"
        )
        lay.addWidget(email)

        note = QLabel(
            "Coloca el archivo  license.key  recibido en:\n"
            f"{_LIC_KEY_FILE}"
        )
        note.setAlignment(Qt.AlignCenter)
        note.setStyleSheet("color:#484f58;font-size:10px;")
        note.setWordWrap(True)
        lay.addWidget(note)

        btn = QPushButton("Cerrar")
        btn.setStyleSheet("background:#21262d;color:#8b949e;")
        btn.clicked.connect(self.close)
        lay.addWidget(btn, alignment=Qt.AlignCenter)


class TrialBanner(QLabel):
    """Small non-intrusive banner shown at top of main window during trial."""

    def __init__(self, days_remaining: int) -> None:
        if days_remaining <= 0:
            days_remaining = 1
        plural = "día" if days_remaining == 1 else "días"
        super().__init__(
            f"  ⏱  Versión de prueba  —  {days_remaining} {plural} restante{'s' if days_remaining != 1 else ''}."
            f"  Solicita tu licencia en: hacklabosofficial@proton.me"
        )
        self.setFixedHeight(26)
        color = "#d29922" if days_remaining > 1 else "#f85149"
        self.setStyleSheet(
            f"background:{color}22;color:{color};"
            "font-size:10px;border-bottom:1px solid "
            f"{color}55;padding-left:8px;"
        )


# ──────────────────────────────────────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("DroneHunter")
    app.setApplicationVersion(__version__)

    # ── Trial / license check ────────────────────────────────────────────────
    valid, days_left = _trial_status()
    if not valid:
        dlg = TrialExpiredDialog()
        dlg.show()
        sys.exit(app.exec_())

    # ── License agreement ────────────────────────────────────────────────────
    lic = LicenseDialog()
    lic.show()
    app.exec_()
    if not lic.accepted:
        sys.exit(0)

    # ── Main window ──────────────────────────────────────────────────────────
    win = DroneHunterWindow()
    # Show trial banner if no full license
    if not _check_license_key():
        trial_banner = TrialBanner(days_left)
        # Insert above the central widget
        container = QWidget()
        vlay = QVBoxLayout(container)
        vlay.setContentsMargins(0, 0, 0, 0)
        vlay.setSpacing(0)
        vlay.addWidget(trial_banner)
        vlay.addWidget(win.centralWidget())
        win.setCentralWidget(container)
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
