"""Standalone RF / electromagnetics calculator utilities.

Pure Python standard library; no third-party dependencies.

Conventions
-----------
* Internal math uses SI base units: frequency in hertz (Hz), length in
  meters (m), power in watts (W).
* Decibel quantities use the power convention (10 * log10) except where
  the input is an amplitude ratio: the reflection coefficient uses
  20 * log10, which still expresses a power ratio.
* ``gamma`` always means the magnitude of the voltage reflection
  coefficient |Gamma| (dimensionless, in [0, 1)).
* Physically invalid inputs raise ``ValueError``.

Run ``python rf_calc.py`` for a labeled self-check against known anchors.
"""

from __future__ import annotations

import math

__all__ = [
    "SPEED_OF_LIGHT",
    "to_hz",
    "from_hz",
    "freq_to_wavelength",
    "wavelength_to_freq",
    "dbm_to_watts",
    "watts_to_dbm",
    "db_to_linear",
    "linear_to_db",
    "fspl_db",
    "friis_rx_dbm",
    "quarter_wave_len",
    "half_wave_len",
    "vswr_to_gamma",
    "gamma_to_vswr",
    "gamma_to_return_loss_db",
    "return_loss_to_gamma",
]

SPEED_OF_LIGHT: float = 299_792_458.0
"""Speed of light in vacuum, in meters per second (exact by SI definition)."""

_FREQ_UNIT_SCALE: dict[str, float] = {
    "hz": 1.0,
    "khz": 1e3,
    "mhz": 1e6,
    "ghz": 1e9,
}


def _require_positive(name: str, value: float) -> None:
    """Raise ValueError unless ``value`` is strictly positive."""
    if value <= 0:
        raise ValueError(f"{name} must be > 0, got {value!r}")


def _require_velocity_factor(velocity_factor: float) -> None:
    """Raise ValueError unless ``velocity_factor`` is in (0, 1]."""
    if not 0.0 < velocity_factor <= 1.0:
        raise ValueError(f"velocity_factor must be in (0, 1], got {velocity_factor!r}")


def _require_gamma(gamma: float) -> None:
    """Raise ValueError unless ``gamma`` is in [0, 1)."""
    if not 0.0 <= gamma < 1.0:
        raise ValueError(
            f"gamma (reflection coefficient magnitude) must be in [0, 1), got {gamma!r}"
        )


def _freq_unit_scale(unit: str) -> float:
    """Hz-per-unit scale factor for 'Hz' / 'kHz' / 'MHz' / 'GHz' (case-insensitive)."""
    try:
        return _FREQ_UNIT_SCALE[unit.lower()]
    except KeyError:
        raise ValueError(
            f"unknown frequency unit {unit!r}; expected one of Hz, kHz, MHz, GHz"
        ) from None


def to_hz(value: float, unit: str = "Hz") -> float:
    """Convert a frequency to hertz.

    Formula: freq_hz = value * scale(unit), with scale Hz=1, kHz=1e3,
    MHz=1e6, GHz=1e9.
    Units: ``value`` in ``unit`` (case-insensitive); returns Hz.

    Raises ValueError on a non-positive frequency or an unknown unit.
    """
    scale = _freq_unit_scale(unit)
    _require_positive("frequency", value)
    return value * scale


def from_hz(freq_hz: float, unit: str = "Hz") -> float:
    """Convert a frequency in hertz to Hz / kHz / MHz / GHz.

    Formula: value = freq_hz / scale(unit), with scale Hz=1, kHz=1e3,
    MHz=1e6, GHz=1e9.
    Units: ``freq_hz`` in Hz; returns frequency in ``unit`` (case-insensitive).

    Raises ValueError on a non-positive frequency or an unknown unit.
    """
    scale = _freq_unit_scale(unit)
    _require_positive("freq_hz", freq_hz)
    return freq_hz / scale


def freq_to_wavelength(freq_hz: float) -> float:
    """Free-space wavelength of an electromagnetic wave.

    Formula: wavelength = c / f
    Units: ``freq_hz`` in Hz; returns wavelength in meters.

    Raises ValueError if ``freq_hz`` is not positive.
    """
    _require_positive("freq_hz", freq_hz)
    return SPEED_OF_LIGHT / freq_hz


def wavelength_to_freq(wavelength_m: float) -> float:
    """Frequency of an electromagnetic wave from its free-space wavelength.

    Formula: f = c / wavelength
    Units: ``wavelength_m`` in meters; returns frequency in Hz.

    Raises ValueError if ``wavelength_m`` is not positive.
    """
    _require_positive("wavelength_m", wavelength_m)
    return SPEED_OF_LIGHT / wavelength_m


def dbm_to_watts(dbm: float) -> float:
    """Convert power in dBm (dB relative to 1 mW) to watts.

    Formula: P_W = 10 ** ((P_dBm - 30) / 10)
    Units: ``dbm`` in dBm; returns power in watts.
    """
    return 10.0 ** ((dbm - 30.0) / 10.0)


def watts_to_dbm(watts: float) -> float:
    """Convert power in watts to dBm (dB relative to 1 mW).

    Formula: P_dBm = 10 * log10(P_W) + 30
    Units: ``watts`` in W; returns power in dBm.

    Raises ValueError if ``watts`` is not positive.
    """
    _require_positive("watts", watts)
    return 10.0 * math.log10(watts) + 30.0


def db_to_linear(db: float) -> float:
    """Convert a power ratio in decibels to a linear ratio.

    Formula: ratio = 10 ** (dB / 10)   (power convention, factor of 10)
    Units: ``db`` in dB; returns a dimensionless power ratio.
    """
    return 10.0 ** (db / 10.0)


def linear_to_db(ratio: float) -> float:
    """Convert a linear power ratio to decibels.

    Formula: dB = 10 * log10(ratio)   (power convention, factor of 10)
    Units: ``ratio`` is a dimensionless power ratio; returns dB.

    Raises ValueError if ``ratio`` is not positive.
    """
    _require_positive("ratio", ratio)
    return 10.0 * math.log10(ratio)


def fspl_db(distance_m: float, freq_hz: float) -> float:
    """Free-space path loss between isotropic antennas, in dB.

    Formula: FSPL_dB = 20*log10(d) + 20*log10(f) + 20*log10(4*pi / c)
    i.e. FSPL = (4*pi*d*f / c)**2 expressed in dB. The constant term is
    derived from c (not the rounded textbook 32.45 / -147.55 dB), so the
    result is exact; it matches 20*log10(d_km) + 20*log10(f_MHz) + 32.45.
    Units: ``distance_m`` in meters, ``freq_hz`` in Hz; returns dB.

    Raises ValueError if distance or frequency is not positive.
    """
    _require_positive("distance_m", distance_m)
    _require_positive("freq_hz", freq_hz)
    return (
        20.0 * math.log10(distance_m)
        + 20.0 * math.log10(freq_hz)
        + 20.0 * math.log10(4.0 * math.pi / SPEED_OF_LIGHT)
    )


def friis_rx_dbm(
    pt_dbm: float,
    gt_dbi: float,
    gr_dbi: float,
    distance_m: float,
    freq_hz: float,
) -> float:
    """Received power over a free-space link (Friis transmission equation, log form).

    Formula: P_rx_dBm = P_tx_dBm + G_tx_dBi + G_rx_dBi - FSPL_dB(d, f)
    Units: ``pt_dbm`` in dBm, gains in dBi, ``distance_m`` in meters,
    ``freq_hz`` in Hz; returns received power in dBm.

    Raises ValueError if distance or frequency is not positive.
    """
    return pt_dbm + gt_dbi + gr_dbi - fspl_db(distance_m, freq_hz)


def quarter_wave_len(freq_hz: float, velocity_factor: float = 1.0) -> float:
    """Physical length of a quarter-wave antenna element.

    Formula: L = (c / f) / 4 * velocity_factor
    Units: ``freq_hz`` in Hz; returns length in meters. ``velocity_factor``
    is the dimensionless wave-velocity ratio of the element (1.0 = free
    space; typical insulated wire ~0.95, coax ~0.66); must be in (0, 1].

    Raises ValueError if ``freq_hz`` is not positive or ``velocity_factor``
    is outside (0, 1].
    """
    _require_velocity_factor(velocity_factor)
    return freq_to_wavelength(freq_hz) / 4.0 * velocity_factor


def half_wave_len(freq_hz: float, velocity_factor: float = 1.0) -> float:
    """Physical length of a half-wave antenna element.

    Formula: L = (c / f) / 2 * velocity_factor
    Units: ``freq_hz`` in Hz; returns length in meters. ``velocity_factor``
    is the dimensionless wave-velocity ratio of the element (1.0 = free
    space); must be in (0, 1].

    Raises ValueError if ``freq_hz`` is not positive or ``velocity_factor``
    is outside (0, 1].
    """
    _require_velocity_factor(velocity_factor)
    return freq_to_wavelength(freq_hz) / 2.0 * velocity_factor


def vswr_to_gamma(vswr: float) -> float:
    """Reflection coefficient magnitude |Gamma| from VSWR.

    Formula: |Gamma| = (VSWR - 1) / (VSWR + 1)
    Units: dimensionless; ``vswr`` must be >= 1; returns |Gamma| in [0, 1).

    Raises ValueError if ``vswr`` < 1.
    """
    if vswr < 1.0:
        raise ValueError(f"vswr must be >= 1, got {vswr!r}")
    return (vswr - 1.0) / (vswr + 1.0)


def gamma_to_vswr(gamma: float) -> float:
    """VSWR from reflection coefficient magnitude |Gamma|.

    Formula: VSWR = (1 + |Gamma|) / (1 - |Gamma|)
    Units: dimensionless; ``gamma`` in [0, 1); returns VSWR >= 1.

    Raises ValueError if ``gamma`` is outside [0, 1).
    """
    _require_gamma(gamma)
    return (1.0 + gamma) / (1.0 - gamma)


def gamma_to_return_loss_db(gamma: float) -> float:
    """Return loss (positive dB) from reflection coefficient magnitude.

    Formula: RL_dB = -20 * log10(|Gamma|)
    (Factor 20, not 10: |Gamma| is an amplitude ratio, and return loss is
    the reflected power ratio -10*log10(|Gamma|**2).)
    Units: ``gamma`` dimensionless in [0, 1); returns positive dB.
    A perfect match (``gamma == 0``) returns ``math.inf``.

    Raises ValueError if ``gamma`` is outside [0, 1).
    """
    _require_gamma(gamma)
    if gamma == 0.0:
        return math.inf
    return -20.0 * math.log10(gamma)


def return_loss_to_gamma(rl_db: float) -> float:
    """Reflection coefficient magnitude from return loss.

    Formula: |Gamma| = 10 ** (-RL_dB / 20)
    Units: ``rl_db`` in dB (positive-dB convention); returns dimensionless
    |Gamma| in (0, 1).

    Raises ValueError if ``rl_db`` is not positive (RL <= 0 dB would imply
    |Gamma| >= 1, a non-passive reflection).
    """
    _require_positive("rl_db", rl_db)
    return 10.0 ** (-rl_db / 20.0)


def _self_check() -> None:
    """Print labeled results and assert each against known anchor values."""

    def check(label: str, actual: float, expected: float, rel_tol: float = 1e-3) -> None:
        print(f"  {label:<60} {actual:>14.9g}   (expected ~ {expected:g})")
        assert math.isclose(actual, expected, rel_tol=rel_tol), (
            f"{label}: got {actual!r}, expected ~{expected!r} (rel_tol={rel_tol})"
        )

    print("rf_calc self-check -- anchors")
    f_24ghz = to_hz(2.4, "GHz")
    check("to_hz(2.4, 'GHz')  [Hz]", f_24ghz, 2.4e9, rel_tol=1e-12)
    check("freq_to_wavelength(2.4 GHz)  [m]", freq_to_wavelength(f_24ghz), 0.12491)
    check("quarter_wave_len(2.4 GHz)  [m]", quarter_wave_len(f_24ghz), 0.03123)
    check("dbm_to_watts(0 dBm)  [W]", dbm_to_watts(0.0), 0.001)
    check("dbm_to_watts(30 dBm)  [W]", dbm_to_watts(30.0), 1.0)
    check("db_to_linear(10 dB)  [x]", db_to_linear(10.0), 10.0)
    check("db_to_linear(3 dB)  [x]", db_to_linear(3.0), 1.995)
    check("fspl_db(1 km, 100 MHz)  [dB]", fspl_db(1_000.0, to_hz(100.0, "MHz")), 72.45)
    check(
        "friis_rx_dbm(Pt=20 dBm, Gt=Gr=3 dBi, 1 km, 100 MHz)  [dBm]",
        friis_rx_dbm(20.0, 3.0, 3.0, 1_000.0, to_hz(100.0, "MHz")),
        -46.45,
    )
    gamma = vswr_to_gamma(2.0)
    check("vswr_to_gamma(2.0)  [|Gamma|]", gamma, 0.3333)
    check("gamma_to_return_loss_db(|Gamma| of VSWR 2)  [dB]",
          gamma_to_return_loss_db(gamma), 9.54)

    print("rf_calc self-check -- round trips")
    check("wavelength_to_freq(freq_to_wavelength(2.4 GHz))  [Hz]",
          wavelength_to_freq(freq_to_wavelength(f_24ghz)), f_24ghz, rel_tol=1e-9)
    check("watts_to_dbm(dbm_to_watts(17 dBm))  [dBm]",
          watts_to_dbm(dbm_to_watts(17.0)), 17.0, rel_tol=1e-9)
    check("linear_to_db(db_to_linear(3 dB))  [dB]",
          linear_to_db(db_to_linear(3.0)), 3.0, rel_tol=1e-9)
    check("gamma_to_vswr(vswr_to_gamma(2.0))  [VSWR]",
          gamma_to_vswr(gamma), 2.0, rel_tol=1e-9)
    check("return_loss_to_gamma(gamma_to_return_loss_db(|Gamma|))",
          return_loss_to_gamma(gamma_to_return_loss_db(gamma)), gamma, rel_tol=1e-9)
    check("half_wave_len(2.4 GHz) == 2 * quarter_wave_len(2.4 GHz)",
          half_wave_len(f_24ghz), 2.0 * quarter_wave_len(f_24ghz), rel_tol=1e-12)

    print("All self-checks passed.")


if __name__ == "__main__":
    _self_check()
